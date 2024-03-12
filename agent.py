import socket
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import IntEnum


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
        raise ValueError("Not an integer")

    return int.from_bytes(content, "big"), len(content) + 2


def decode_tlv(message: bytes) -> tuple[Asn1DataType, bytes]:
    if message[0] not in Asn1DataType:
        raise ValueError(f"Unknown data type: {hex(message[0])}")

    length = message[1]
    if length & 0b1000000:
        raise ValueError("Indefinite length not supported")

    return Asn1DataType(message[0]), message[2 : 2 + length]


class SNMPMessage:
    def __init__(self, message) -> None:
        if not message:
            raise ValueError("Message empty")

        if message[0] != Asn1DataType.SEQUENCE:
            raise ValueError("Not a sequence")

        self.version, length = read_tlv_int(message[2:])
        message = message[2 + length :]

        data_type, self.community = decode_tlv(message)
        if data_type != Asn1DataType.OCTET_STRING:
            raise ValueError("Community not octet string")


def main(args: list[str]) -> None:
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=161, type=int)
    args = parser.parse_args(args)
    port = args.port
    bufsize = 2048

    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))

    store = {
        "some integer": Object(
            Asn1DataType.INTEGER, length=1, value=1, max_access=MaxAccess.read_only
        ),
        "some integer 2": Object(
            Asn1DataType.INTEGER, length=1, value=2, max_access=MaxAccess.read_write
        ),
    }

    while True:
        message, addr = sock.recvfrom(bufsize)
        print(f"Received message from {addr} ({len(message)}): {message.hex(' ', 1)}")


if __name__ == "__main__":
    main(sys.argv[1:])
