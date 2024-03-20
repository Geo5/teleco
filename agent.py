"""Module implementing a simple SNMP agent."""

from __future__ import annotations

import socket
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum
from typing import Self, TypeVar, cast


class Asn1DataType(IntEnum):
    """Asn1 data type."""

    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL_asn1 = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    IpAddress = 0x40
    Gauge32 = 0x42
    # CHOICE has a context specific tag (encoded as 0b10[1|0]0_0000 )
    # Value is > 0xFF, so it cannot occur as normal asn1 type,
    # because the length of the type is 1 byte (max 0xFF)
    CHOICE = 0xFFF


class MaxAccess(IntEnum):
    """Object access permission."""

    not_accessible = 0
    read_only = 1
    read_write = 2


class ObjectType(IntEnum):
    """Managed object type."""

    scalar = 0
    table = 1
    row = 2
    column = 3


class ErrorStatus(IntEnum):
    """SNMP message error status."""

    noError = 0
    tooBig = 1
    noSuchName = 2
    badValue = 3
    readOnly = 4
    genErr = 5


@dataclass
class VariableBind:
    """SNMP message variable bindings.

    Type of value depends on data_type.
    """

    oid: str
    data_type: Asn1DataType
    value: int | bytes | str | None


@dataclass
class Object:
    """Managed objects.

    Type of value depends on data_type.
    """

    data_type: Asn1DataType
    value: int | bytes | str | None
    object_type: ObjectType = ObjectType.scalar
    max_access: MaxAccess = MaxAccess.not_accessible


def decode_tlv(buffer: bytes) -> tuple[bytes, Asn1DataType, bytes | None]:
    """Decode on tlv encoded value from a buffer of bytes.

    Args:
    ----
        buffer: Buffer of bytes to read from.

    Raises:
    ------
        ValueError:
            - If the length encoding is not supported.
            - If the ASN1 data type is not supported.
            - If the buffer is too short.

    Returns:
    -------
        The remaining (unread) buffer, the decoded data type, the value.

    """
    # We need a minimum of 2 bytes - [type, length]
    if len(buffer) < 2:
        msg = "Empty buffer"
        raise ValueError(msg)
    # Check if have a context specific tag
    if buffer[0] & 0b1000_0000:
        # Check if we have a constructed tag (can contain other values)
        data_type = Asn1DataType.CHOICE
        # Add the concrete choice type as attribute
        data_type.tag = buffer[0] & 0b0001_111
        if not (buffer[0] & 0b0010_0000):
            # We do not need to decode the length, if we don't have a constructed tag
            return buffer[2:], data_type, None
    else:
        # Decode type
        data_type = Asn1DataType(buffer[0])
    # Decode length
    length = buffer[1]
    if length & 0b1000000:
        msg = "Indefinite length not supported"
        raise ValueError(msg)
    # Check if buffer is long
    if len(buffer) < length + 2:
        msg = f"Buffer is too small (is {len(buffer)}, wants {length+2})"
        raise ValueError(msg)

    return buffer[2 + length :], data_type, buffer[2 : 2 + length]


def decode_tlv_value(
    buffer: bytes,
) -> tuple[bytes, Asn1DataType, int | str | bytes | None]:
    """Like decode_tlv but tries to decode the resulting value to a concrete type."""
    buffer, data_type, raw_value = decode_tlv(buffer)
    if raw_value is None:
        return buffer, data_type, raw_value
    match data_type:
        case Asn1DataType.INTEGER:
            value: int | str | bytes | None = int.from_bytes(raw_value, "big")
        case Asn1DataType.OCTET_STRING:
            value = raw_value.decode("ASCII")
        case _:
            value = raw_value

    return buffer, data_type, value


def read_tlv_int(buffer: bytes) -> tuple[bytes, int]:
    """Read an BER encoded int.

    Args:
    ----
        buffer: Buffer of bytes to read from.

    Raises:
    ------
        ValueError: If value is not an integer.

    Returns:
    -------
        The remaining (unread) buffer, the decoded integer.

    """
    buffer, data_type, value = decode_tlv(buffer)
    if data_type != Asn1DataType.INTEGER or value is None:
        msg = f"Not an integer (is {data_type})"
        raise ValueError(msg)

    return buffer, int.from_bytes(value, "big")


def read_tlv_string(buffer: bytes) -> tuple[bytes, str]:
    """Read an encoded string.

    Args:
    ----
        buffer: Buffer of bytes to read from.

    Raises:
    ------
        ValueError: If value is not a string.

    Returns:
    -------
        The remaining (unread) buffer, the decoded string.

    """
    buffer, data_type, value = decode_tlv(buffer)
    if data_type != Asn1DataType.OCTET_STRING or value is None:
        msg = f"Not a string (is {data_type})"
        raise ValueError(msg)

    return buffer, value.decode("ASCII")


def read_tlv_sequence(buffer: bytes) -> tuple[bytes, bytes]:
    """Read a sequence and its contents.

    Args:
    ----
        buffer: Buffer of bytes to read from.

    Returns:
    -------
        The remaining (unread) buffer, the contents of the sequence

    """
    buffer, data_type, value = decode_tlv(buffer)
    if data_type != Asn1DataType.SEQUENCE or value is None:
        msg = f"Not a sequence (is {data_type})"
        raise ValueError(msg)

    return buffer, value


CT = TypeVar("CT", bound=IntEnum)


def read_tlv_choice(buffer: bytes, choices: type[CT]) -> tuple[bytes, CT, bytes | None]:
    """Read a choice value and its contents.

    Args:
    ----
        buffer: Buffer of bytes to read from.
        choices: The available choices.

    Returns:
    -------
        - The remaining (unread) buffer
        - The choice value,
        - The contents if the type is constructed.

    """
    buffer, data_type, value = decode_tlv(buffer)
    if data_type != Asn1DataType.CHOICE:
        msg = f"Not a choice (is {data_type})"
        raise ValueError(msg)

    return buffer, choices(data_type.tag), value


def decode_oid(value: bytes) -> str:
    """Decode OID number from bytes."""
    # First byte contains 2 numbers
    oid = [(value[0] & 0xEF) // 40, (value[0] & 0xEF) % 40]
    # Other bytes contain 1 number each, the highest bit is not used
    oid.extend(byte & 0xEF for byte in value[1:])

    return ".".join(str(o) for o in oid)


def read_tlv_oid(buffer: bytes) -> tuple[bytes, str]:
    """Read an encoded object identifier.

    Args:
    ----
        buffer: Buffer of bytes to read from.

    Raises:
    ------
        ValueError: If value is not an object identifier.

    Returns:
    -------
        The remaining (unread) buffer, the decoded oid.

    """
    buffer, data_type, value = decode_tlv(buffer)
    if data_type != Asn1DataType.OBJECT_IDENTIFIER or value is None:
        msg = f"Not an oid (is {data_type})"
        raise ValueError(msg)

    return buffer, decode_oid(value)


def encode_length(value: int) -> bytes:
    """Encode length for BER."""
    # If length fits in 7 bits, we can encode it directly
    if value <= 0xEF:
        return value.to_bytes(1, "big")
    # Otherwise we encode it like an integer
    enc = encode_lv_int(value)
    # We need to set the first bit to 1
    enc = bytes(enc[0] | 0b1000_0000) + enc[1:]
    return enc


def encode_lv_oid(value: str) -> bytes:
    """Encode oid into bytes with length.

    Args:
    ----
        value: The oid value.

    Returns:
    -------
        bytes: Buffer containing length and value information.

    """
    oid = [int(o) for o in value.split(".")]
    # First byte contains 2 numbers
    enc = (oid[0] * 40 + oid[1]).to_bytes(1, "big")
    # Other bytes contain 1 number each, the highest bit is not used
    for o in oid[2:]:
        enc += o.to_bytes(1, "big")
    return encode_length(len(enc)) + enc


def encode_lv_int(value: int) -> bytes:
    """Encode integer into bytes with length.

    Args:
    ----
        value: The integer value.

    Returns:
    -------
        bytes: Buffer containing length and value information.

    """
    # The minimum length is 1 byte, even if the value == 0
    enc = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return encode_length(len(enc)) + enc


def encode_tlv_value(data_type: Asn1DataType, value: int | str | bytes) -> bytes:
    """Encode any value using tlv.

    Args:
    ----
        data_type: Data type of value.
        value (int | str | bytes): Value in type depending on data_type.

    Returns:
    -------
        bytes: Encoded bytes.

    """
    if data_type > 0xFF:
        msg = f"Cannot encode data type {data_type}"
        raise ValueError(msg)
    buffer = bytes([data_type])

    match data_type:
        case Asn1DataType.NULL_asn1:
            buffer += bytes([0x00])
        case Asn1DataType.INTEGER:
            buffer += encode_lv_int(value)
        case Asn1DataType.OBJECT_IDENTIFIER:
            buffer += encode_lv_oid(value)
        case Asn1DataType.SEQUENCE:
            value = cast(bytes, value)
            buffer += encode_length(len(value)) + value
        case Asn1DataType.OCTET_STRING:
            value = cast(str, value)
            enc = value.encode("ASCII")
            buffer += encode_length(len(enc)) + enc
        case _:
            raise NotImplementedError

    return buffer


def encode_tlv_choice(value: IntEnum, content: bytes) -> bytes:
    """Encode a choice with contents."""
    return bytes([0b1010_0000 | value]) + encode_length(len(content)) + content


class PDUType(IntEnum):
    """SNMP request type."""

    GetRequest = 0
    GetNextRequest = 1
    GetResponse = 2
    SetRequest = 3


@dataclass
class SNMPMessage:
    """SNMP message object."""

    version: int
    community: str
    pdu_type: PDUType
    request_id: int
    error_status: ErrorStatus
    error_index: int
    variable_bindings: list[VariableBind]

    @classmethod
    def from_bytes(cls, buffer: bytes) -> tuple[SNMPMessage, bytes]:
        """Construct SNMP message from bytes.

        Args:
        ----
            buffer: The bytes to read from.

        Returns:
        -------
            The constructed message, the remaining (unread) buffer.

        """
        remaining, buffer = read_tlv_sequence(buffer)

        buffer, version = read_tlv_int(buffer)

        buffer, community = read_tlv_string(buffer)

        _, pdu_type, buffer = read_tlv_choice(buffer, PDUType)
        buffer, request_id = read_tlv_int(buffer)

        buffer, error_status_number = read_tlv_int(buffer)
        error_status = ErrorStatus(error_status_number)

        buffer, error_index = read_tlv_int(buffer)

        # Sequence of variable bindings
        _, buffer = read_tlv_sequence(buffer)
        variable_bindings = []
        while buffer:
            # Variable binding is also sequence type
            buffer, var = read_tlv_sequence(buffer)
            var, oid = read_tlv_oid(var)
            _, data_type, value = decode_tlv_value(var)
            variable_bindings.append(VariableBind(oid, data_type, value))

        return SNMPMessage(
            version,
            community,
            pdu_type,
            request_id,
            error_status,
            error_index,
            variable_bindings,
        ), remaining

    def encode_tlv(self) -> bytes:
        """Encode message using tlv encoding."""
        buffer = encode_tlv_value(Asn1DataType.INTEGER, self.request_id)
        buffer += encode_tlv_value(Asn1DataType.INTEGER, self.error_status)
        buffer += encode_tlv_value(Asn1DataType.INTEGER, self.error_index)
        variables = b""
        for var in self.variable_bindings:
            var_enc = encode_tlv_value(Asn1DataType.OBJECT_IDENTIFIER, var.oid)
            var_enc += encode_tlv_value(var.data_type, var.value)
            variables += encode_tlv_value(Asn1DataType.SEQUENCE, var_enc)
        buffer += encode_tlv_value(Asn1DataType.SEQUENCE, variables)

        buffer = encode_tlv_choice(self.pdu_type, buffer)
        buffer = encode_tlv_value(Asn1DataType.OCTET_STRING, self.community) + buffer
        buffer = encode_tlv_value(Asn1DataType.INTEGER, self.version) + buffer

        return encode_tlv_value(Asn1DataType.SEQUENCE, buffer)

    def response(self) -> SNMPMessage:
        """Construct a response to a message.

        Variable bindings (in case of a GetRequest message) need to be changed
        afterwards by manually changing self.variable_bindings.

        error_status and error_index are not changed.

        Returns
        -------
            A new SNMPMessage object containing copied values from self.

        """
        match self.pdu_type:
            case PDUType.GetRequest | PDUType.SetRequest | PDUType.GetNextRequest:
                # Response to GetRequest and SetRequest is GetResponse
                new_pdu_type = PDUType.GetResponse
            case _:
                raise NotImplementedError

        return SNMPMessage(
            self.version,
            self.community,
            new_pdu_type,
            self.request_id,
            ErrorStatus.noError,
            0,
            self.variable_bindings.copy(),
        )


# Setup managed objects
MANAGED_OBJECTS = {
    # Entered
    "1.3.6.1.3.1.0": Object(
        Asn1DataType.INTEGER,
        0,
        max_access=MaxAccess.read_write,
    ),
    # Left
    "1.3.6.1.3.2.0": Object(
        Asn1DataType.INTEGER,
        0,
        max_access=MaxAccess.read_write,
    ),
}


def get_next(oid: str) -> tuple[str, Object] | tuple[None, None]:
    """Get next accessible element in the MIB for a given OID.

    Args:
    ----
        oid: The original OID.

    Returns:
    -------
        The next OID and the next managed object in the MIB or None if none exists.

    """
    # Sort objects by OID lexicographically
    objects = sorted(MANAGED_OBJECTS.items(), key=lambda t: t[0])
    # Get first object which is accessible and has a greater OID
    next_oid, next_obj = next(
        (
            (o, obj)
            for o, obj in objects
            if o > oid and obj.max_access != MaxAccess.not_accessible
        ),
        (None, None),
    )
    return next_oid, next_obj


def handle_snmp_message(message: SNMPMessage) -> SNMPMessage:
    """Construct response message and handle possible action.

    Args:
    ----
        message: The incoming SNMP request message.

    Returns:
    -------
        The response SNMP message.

    """
    response = message.response()
    match message.pdu_type:
        case PDUType.GetRequest:
            # Look up all OIDs in the objects map
            # and construct a new list of variable bindings with the values found there
            new_var_bindings = []
            for idx, var in enumerate(message.variable_bindings):
                # Check if OID exists
                if (
                    not (obj := MANAGED_OBJECTS.get(var.oid, None))
                    or obj.max_access == MaxAccess.not_accessible
                ):
                    # OID does not exist or is not accessible
                    # Set error status and index
                    response.error_index = idx
                    response.error_status = ErrorStatus.noSuchName
                    # Return otherwise identical message
                    return response
                # Update variable binding with type and value
                new_var_bindings.append(
                    VariableBind(var.oid, obj.data_type, obj.value),
                )
            # Update the variable bindings
            response.variable_bindings = new_var_bindings
        case PDUType.SetRequest:
            # First check if all variable bindings are valid
            for idx, var in enumerate(message.variable_bindings):
                # Check if OID exists and we have write access
                if (
                    not (obj := MANAGED_OBJECTS.get(var.oid, None))
                    or obj.max_access != MaxAccess.read_write
                ):
                    response.error_index = idx
                    response.error_status = ErrorStatus.noSuchName
                    return response
                # Check if type is compatible
                if obj.data_type != var.data_type:
                    response.error_index = idx
                    response.error_status = ErrorStatus.badValue
                    return response
            # Only after making sure all are valid, set the values
            for var in message.variable_bindings:
                # Set the new value
                MANAGED_OBJECTS[var.oid].value = var.value
                # We don't need to update the variable bindings here, because the value is
                # set to the value contained in the incoming request.
        case PDUType.GetNextRequest:
            new_var_bindings = []
            for idx, var in enumerate(message.variable_bindings):
                # Find the next OID in the objects map
                next_oid, next_object = get_next(var.oid)
                # If no new next element exists, we set the error status
                if next_oid is None or next_object is None:
                    response.error_index = idx
                    response.error_status = ErrorStatus.noSuchName
                    # Return otherwise identical message
                    return response
                # Update variable binding with type and value
                new_var_bindings.append(
                    VariableBind(next_oid, next_object.data_type, next_object.value),
                )
            # Update the variable bindings
            response.variable_bindings = new_var_bindings
    return response


def main(args_: list[str]) -> None:
    """Main function."""
    # Parse command line arguments
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=161, type=int)
    args = parser.parse_args(args_)
    port = args.port
    host = "127.0.0.1"
    # Setup socket
    bufsize = 2048
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind((host, port))
    # Add device IP to managed objects
    MANAGED_OBJECTS["1.3.6.1.3.3.0"] = Object(
        Asn1DataType.IpAddress,
        host,
        max_access=MaxAccess.read_write,
    )
    # Read-write loop
    while True:
        # Receive message
        message, addr = sock.recvfrom(bufsize)
        print(f"Received message from {addr} ({len(message)}): {message.hex(' ', 1)}")
        # Parse SNMP message into object
        snmp_message, _ = SNMPMessage.from_bytes(message)
        print(snmp_message)
        # Construct response and handle possible action (SetRequest)
        response = handle_snmp_message(snmp_message)
        # Send response back
        print(f"Response is {response}")
        sock.sendto(response.encode_tlv(), addr)


if __name__ == "__main__":
    main(sys.argv[1:])
