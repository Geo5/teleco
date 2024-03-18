"""Module implementing a simple SNMP agent."""

from __future__ import annotations

import socket
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum
from typing import Self, TypeVar


class Asn1DataType(IntEnum):
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL_asn1 = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    IpAddress = 0x40
    Gauge32 = 0x42
    # CHOICE has a context specific tag ( 0b10[1|0]00000 )
    CHOICE = 0xFFF


class MaxAccess(IntEnum):
    not_accessible = 0
    read_only = 1
    read_write = 2


class ObjectType(IntEnum):
    scalar = 0
    table = 1
    row = 2
    column = 3


class ErrorStatus(IntEnum):
    noError = 0
    tooBig = 1
    noSuchName = 2
    badValue = 3
    readOnly = 4
    genErr = 5


@dataclass
class VariableBind:
    oid: str
    data_type: Asn1DataType
    value: int | bytes


@dataclass
class Object:
    data_type: Asn1DataType
    value: int | bytes
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
    buffer, data_type, value = decode_tlv(buffer)
    match data_type:
        case Asn1DataType.INTEGER:
            value = int.from_bytes(value, "big")
        case Asn1DataType.OCTET_STRING:
            value = value.decode("ASCII")

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
    if data_type != Asn1DataType.INTEGER:
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
    if data_type != Asn1DataType.OCTET_STRING:
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
    if data_type != Asn1DataType.SEQUENCE:
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
    if data_type != Asn1DataType.OBJECT_IDENTIFIER:
        msg = f"Not an oid (is {data_type})"
        raise ValueError(msg)

    return buffer, decode_oid(value)


def encode_length(value: int) -> bytes:
    """Encode length for BER."""
    if value <= 0xEF:
        return value.to_bytes(1, "big")
    return encode_lv_int(value)


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
            buffer += encode_length(len(value)) + value
        case Asn1DataType.OCTET_STRING:
            enc = value.encode("ASCII")
            buffer += encode_length(len(enc)) + enc
        case _:
            raise NotImplementedError

    return buffer


def encode_tlv_choice(value: IntEnum, content: bytes) -> None:
    """Encode a choice with contents."""
    return bytes([0b1010_0000 | value]) + encode_length(len(content)) + content


class PDUType(IntEnum):
    GetRequest = 0
    GetNextRequest = 1
    GetResponse = 2
    SetRequest = 3


@dataclass
class SNMPMessage:
    version: int
    community: str
    pdu_type: PDUType
    request_id: int
    error_status: ErrorStatus
    error_index: int
    variable_bindings: list[VariableBind]

    @classmethod
    def from_bytes(cls, buffer: bytes) -> tuple[Self, bytes]:
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

    def response(self) -> Self:
        """Construct a response to a message."""
        match self.pdu_type:
            case PDUType.GetRequest | PDUType.SetRequest:
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
            self.variable_bindings,
        )


def main(args: list[str]) -> None:
    # Parse command line arguments
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=161, type=int)
    args = parser.parse_args(args)
    port = args.port
    # Setup socket
    bufsize = 2048
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    # Setup data
    objects = {
        # Entered
        "1.3.6.1.3.1.0": Object(
            Asn1DataType.INTEGER, 0, max_access=MaxAccess.read_write
        ),
        # Left
        "1.3.6.1.3.2.0": Object(
            Asn1DataType.INTEGER, 0, max_access=MaxAccess.read_write
        ),
    }
    # Read-write loop
    while True:
        message, addr = sock.recvfrom(bufsize)
        print(f"Received message from {addr} ({len(message)}): {message.hex(' ', 1)}")

        snmp_message, _ = SNMPMessage.from_bytes(message)
        print(snmp_message)
        # Handle message
        response = snmp_message.response()
        match snmp_message.pdu_type:
            case PDUType.SetRequest:
                # Update the variables
                for idx, var in enumerate(snmp_message.variable_bindings):
                    # Check if oid exists
                    if var.oid not in objects:
                        response.error_index = idx
                        response.error_status = ErrorStatus.noSuchName
                        break
                    obj = objects[var.oid]
                    # Check if we have write access
                    if obj.max_access != MaxAccess.read_write:
                        response.error_index = idx
                        response.error_status = ErrorStatus.noSuchName
                        break
                    # Check if type is compatible
                    if obj.data_type != var.data_type:
                        response.error_index = idx
                        response.error_status = ErrorStatus.badValue
                        break
                    # Set the new value
                    obj.value = var.value
            case PDUType.GetRequest:
                # Look up all oids in the objects map
                # and construct a new list of variable bindings with the values found there
                new_var_bindings = []
                for idx, var in enumerate(snmp_message.variable_bindings):
                    # Check if name exists
                    if var.oid not in objects:
                        response.error_index = idx
                        response.error_status = ErrorStatus.noSuchName
                        break
                    obj = objects[var.oid]
                    # Update variable binding with type and value
                    new_var_bindings.append(
                        VariableBind(var.oid, obj.data_type, obj.value)
                    )
                response.variable_bindings = new_var_bindings

        print(f"Answer is {response}")
        sock.sendto(response.encode_tlv(), addr)


if __name__ == "__main__":
    main(sys.argv[1:])
