import socket
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum
from typing import Self


class Asn1DataType(IntEnum):
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL_asn1 = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30
    IpAddress = 0x40
    Gauge32 = 0x42


class MaxAccess(IntEnum):
    not_accessible = 0
    read_only = 1
    read_write = 2


class ObjectType(IntEnum):
    scalar = 0
    table = 1
    row = 2
    column = 3


class PDUType(IntEnum):
    GetRequest = 0xA0
    GetNextRequest = 0xA1
    GetResponse = 0xA2
    SetRequest = 0xA3


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
    length: int
    value: int | bytes
    object_type: ObjectType = ObjectType.scalar
    max_access: MaxAccess = MaxAccess.not_accessible


def read_tlv_int(message: bytes) -> tuple[int, int]:
    """Read an BER encoded int."""
    data_type, content = decode_tlv(message)
    if data_type != Asn1DataType.INTEGER:
        raise ValueError(f"Not an integer (is {data_type})")

    return int.from_bytes(content, "big"), len(content) + 2


def decode_tlv(message: bytes) -> tuple[Asn1DataType, bytes]:
    print(message.hex(" ", 1))
    # print(f"{message[0]:b}")
    data_type = Asn1DataType(message[0])

    length = message[1]
    if length & 0b1000000:
        raise ValueError("Indefinite length not supported")

    return data_type, message[2 : 2 + length]


def decode_oid(value: bytes) -> str:
    """Decode OID number."""
    print(f"{value=}")
    print(f"{value[0]=}")
    print(f"{(value[0] & 0xEF) // 40}")
    print(f"{(value[0] % 0xEF) % 40}")
    oids = [(value[0] & 0xEF) // 40, (value[0] & 0xEF) % 40]
    for byte in value[1:]:
        oids.append(byte & 0xEF)

    return ".".join(str(oid) for oid in oids)


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
    def from_bytes(cls, message: bytes) -> Self:
        if not message:
            raise ValueError("Message empty")

        if message[0] != Asn1DataType.SEQUENCE:
            raise ValueError("Not a sequence")

        version, length = read_tlv_int(message[2:])
        message = message[2 + length :]

        data_type, community = decode_tlv(message)
        if data_type != Asn1DataType.OCTET_STRING:
            raise ValueError("Community not octet string")
        message = message[2 + len(community) :]
        # Parse pdu type
        pdu_type = PDUType(message[0])
        message = message[2:]

        request_id, length = read_tlv_int(message)
        message = message[length:]

        error_status_number, length = read_tlv_int(message)
        error_status = ErrorStatus(error_status_number)
        message = message[length:]

        error_index, length = read_tlv_int(message)
        message = message[length:]

        if message[0] != Asn1DataType.SEQUENCE or message[2] != Asn1DataType.SEQUENCE:
            raise ValueError("Invalid message, expected variable bindings sequence")
        message = message[4:]

        variable_bindings = []
        while message:
            data_type, oid = decode_tlv(message)
            if data_type != Asn1DataType.OBJECT_IDENTIFIER:
                raise ValueError("Expected object identifier")
            message = message[len(oid) + 2 :]
            data_type, value = decode_tlv(message)
            message = message[len(value) + 2 :]
            variable_bindings.append(VariableBind(decode_oid(oid), data_type, value))

        return SNMPMessage(
            version,
            community.decode("ASCII"),
            pdu_type,
            request_id,
            error_status,
            error_index,
            variable_bindings,
        )


def main(args: list[str]) -> None:
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=161, type=int)
    args = parser.parse_args(args)
    port = args.port
    bufsize = 2048

    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))

    while True:
        message, addr = sock.recvfrom(bufsize)
        print(f"Received message from {addr} ({len(message)}): {message.hex(' ', 1)}")

        snmp_message = SNMPMessage.from_bytes(message)
        print(snmp_message)


if __name__ == "__main__":
    main(sys.argv[1:])
