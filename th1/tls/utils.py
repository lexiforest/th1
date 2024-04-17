import collections
import enum
import struct
from typing import Any

# Special value to denote GREASE in various placements in the Client Hello.
# Intentionally negative so that it won't conflict with any real field.
TLS_GREASE = -1


class TLSVersion(enum.Enum):
    # See https://github.com/openssl/openssl/blob/master/include/openssl/prov_ssl.h
    TLS_VERSION_1_0 = 0x0301
    TLS_VERSION_1_1 = 0x0302
    TLS_VERSION_1_2 = 0x0303
    TLS_VERSION_1_3 = 0x0304

    # Special value to denote a GREASE randomized value.
    GREASE = TLS_GREASE

    @classmethod
    def has_value(cls, value):
        return value in [x.value for x in cls]


# Possible values for GREASE
TLS_GREASE_VALUES = [
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
]
# Structs for parsing TLS packets
TLS_RECORD_HEADER = "!BHH"
TLSRecordHeader = collections.namedtuple("TLSRecordHeader", "type, version, length")

TLS_HANDSHAKE_HEADER = "!BBHH32sB"
TLSHandshakeHeader = collections.namedtuple(
    "TLSHandshakeHeader",
    "type, length_high, length_low, version, random, session_id_length",
)

TLS_EXTENSION_HEADER = "!HH"
TLSExtensionHeader = collections.namedtuple("TLSExtensionHeader", "type, length")


def serialize_grease(l: list[Any]) -> list[Any]:
    return list(map(lambda x: "GREASE" if x == TLS_GREASE else x, l))


def deserialize_grease(l: list[Any]) -> list[Any]:
    return list(map(lambda x: TLS_GREASE if x == "GREASE" else x, l))


def parse_tls_int_list(
    data: bytes,
    entry_size: int,
    header_size: int = 2,
    replace_grease: bool = True,
) -> tuple[list[int], int]:
    """Parse a TLS-encoded list of integers.

    This list format is common in TLS packets.
    It consists of a two-byte header indicating the total length
    of the list, with the entries following.

    The entries may be one of TLS_GREASE_VALUES, in which case they
    are replaced with the constant TLS_GREASE (unless replace_grease=False).

    Returns
    -------
    entries : list[int]
        List of entries extracted from the TLS-encoded list.
    size : int
        Total size, in bytes, of the list.
    """

    off = 0
    h = "!H" if header_size == 2 else "!B"
    (list_length,) = struct.unpack_from(h, data, off)
    off += struct.calcsize(h)
    if list_length > len(data) - off:
        raise Exception(f"TLS list of integers too long: {list_length} bytes")

    entries = []
    s = "!H" if entry_size == 2 else "!B"
    for _ in range(list_length // entry_size):
        (entry,) = struct.unpack_from(s, data, off)
        off += struct.calcsize(s)
        if replace_grease and entry in TLS_GREASE_VALUES:
            entry = TLS_GREASE
        entries.append(entry)

    return entries, struct.calcsize(h) + list_length


def parse_tls_str_list(data: bytes) -> tuple[list[str], int]:
    """Parse a TLS-encoded list of strings.

    Returns
    -------
    entries : list[str]
        List of entries extracted from the TLS-encoded list.
    size : int
        Total size, in bytes, of the list.
    """
    off = 0
    header_size = struct.calcsize("!H")
    (list_length,) = struct.unpack_from("!H", data, off)
    off += header_size
    if list_length > len(data) - off:
        raise Exception("TLS list of strings too long")

    entries = []
    while off - header_size < list_length:
        (strlen,) = struct.unpack_from("!B", data, off)
        off += struct.calcsize("!B")
        entries.append(data[off : off + strlen].decode())
        off += strlen

    return entries, struct.calcsize("!H") + list_length
