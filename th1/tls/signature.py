import random
import struct
from typing import List

from ..base import Signature
from .extensions import TLSExtensionSignature, TLSExtensionType
from .utils import (
    TLS_EXTENSION_HEADER,
    TLS_HANDSHAKE_HEADER,
    TLS_RECORD_HEADER,
    TLSHandshakeHeader,
    TLSRecordHeader,
    TLSVersion,
    deserialize_grease,
    parse_tls_int_list,
    serialize_grease,
)


class TLSClientHelloSignature(Signature):
    """
    Signature of a TLS Client Hello message.

    Combines multiple parameters from a TLS Client Hello message into a
    signature that is used to check if two such messages are identical, up to
    various random values which may be present.

    Why not use JA3? (https://github.com/salesforce/ja3)
    Our signature is more extensive and covers more parameters. For example, it
    checks whether a session ID is present, or what values are sent inside
    TLS extensions such as ALPN.
    """

    def __init__(
        self,
        record_version: TLSVersion,
        handshake_version: TLSVersion,
        session_id_length: int,
        ciphersuites: List[int],
        comp_methods: List[int],
        extensions: List[TLSExtensionSignature],
    ):
        """
        Initialize a new TLSClientHelloSignature.

        Signatures can be compared with one another to check if they are equal.

        Parameters
        ----------
        record_version : TLSVersion
            Represents the "tls.record.version" field of the Client Hello.
        handshake_version : TLSVersion
            Represents the "tls.handshake.type" field.
        session_id_length : int
            Represents the "tls.handshake.session_id_length" field.
        ciphersuites : list[int]
            Represents the "tls.handshake.ciphersuites" list of ciphersuites.
        comp_methods : list[int]
            Represents the "tls.handshake.comp_methods" list of compression
            methods.
        extensions : list[TLSExtensionSignature]
            Represents the list of TLS extensions in the Client Hello.
        """
        self.record_version = record_version
        self.handshake_version = handshake_version
        self.session_id_length = session_id_length
        self.ciphersuites = ciphersuites
        self.comp_methods = comp_methods
        self.extensions = extensions

    @property
    def relevant_extensions(self):
        # Remove pre-shared key, this extension is only added for the second request to a website
        exts = [ext for ext in self.extensions if ext.ext_type != TLSExtensionType.pre_shared_key]

        # if ech is enabled, whether padding is added depends on the GREASE length
        has_ech = any([ext.ext_type == TLSExtensionType.encrypted_client_hello for ext in exts])
        if has_ech:
            exts = [ext for ext in exts if ext.ext_type != TLSExtensionType.padding]
        return exts

    @property
    def extension_names(self):
        return [ext.ext_type for ext in self.relevant_extensions]

    def _is_permutable_extension(self, ext: TLSExtensionSignature):
        # Chrome permutes all TLS extensions except for GREASE and pre_shared_key
        # (and the trailing padding)
        return ext.ext_type not in [
            TLSExtensionType.GREASE,
            TLSExtensionType.pre_shared_key,
            TLSExtensionType.padding,
        ]

    def permuate(self):
        indexes = []
        permutables = []
        for idx, ex in enumerate(self.extensions):
            if self._is_permutable_extension(ex):
                indexes.append(idx)
                permutables.append(ex)
        random.shuffle(permutables)
        for idx, permutable in zip(indexes, permutables):
            self.extensions[idx] = permutable

    def _compare_extensions(
        self, other: "TLSClientHelloSignature", allow_tls_permutation: bool = False
    ) -> tuple[bool, str]:
        """Compare the TLS extensions of two Client Hello messages."""

        # Check that the extension lists are identical in content.
        if set(self.extension_names) != set(other.extension_names):
            symdiff = list(
                set(self.extension_names).symmetric_difference(other.extension_names)
            )
            return False, (
                f"TLS extension list differ: " f"Symmetric difference {symdiff}"
            )

        if not allow_tls_permutation and self.extension_names != other.extension_names:
            return False, "TLS extension lists identical but differ in order"

        # Check the extensions' parameters.
        for i, ext in enumerate(self.relevant_extensions):
            if allow_tls_permutation and self._is_permutable_extension(ext):
                # If TLS extension permutation is enabled, locate this extension
                # in the other signature by type.
                other_ext = next(
                    e for e in other.relevant_extensions if e.ext_type == ext.ext_type
                )
            else:
                other_ext = other.relevant_extensions[i]
            if not ext.equals(other_ext):
                ours = ext.to_dict()
                ours.pop("type")
                theirs = other_ext.to_dict()
                theirs.pop("type")
                msg = (
                    f"TLS extension {ext.ext_type.name} is different. "
                    f"{ours} != {theirs}"
                )
                return False, msg

        return True, ""

    def equals(
        self, other: "TLSClientHelloSignature", allow_tls_permutation: bool = False
    ) -> tuple[bool, str]:
        """Check if another TLSClientHelloSignature is identical."""

        if self.record_version != other.record_version:
            msg = (
                f"TLS record versions differ: "
                f"{self.record_version} != {other.record_version}"
            )
            return False, msg

        if self.handshake_version != other.handshake_version:
            msg = (
                f"TLS handshake versions differ: "
                f"{self.handshake_version} != "
                f"{other.handshake_version}"
            )
            return False, msg

        if self.session_id_length != other.session_id_length:
            msg = (
                f"TLS session ID lengths differ: "
                f"{self.session_id_length} != {other.session_id_length}"
            )
            return False, msg

        if self.ciphersuites != other.ciphersuites:
            msg = (
                f"TLS ciphersuites differ in contents or order. "
                f"{self._compare_extensions} != {other.ciphersuites}"
            )
            return False, msg

        if self.comp_methods != other.comp_methods:
            msg = (
                "TLS compression methods differ in contents or order. "
                f"{self.comp_methods} != {other.comp_methods}"
            )
            return False, msg

        return self._compare_extensions(other, allow_tls_permutation)

    def to_dict(self):
        """Serialize to a dict object."""
        return {
            "record_version": self.record_version.name,
            "handshake_version": self.handshake_version.name,
            "session_id_length": self.session_id_length,
            "ciphersuites": serialize_grease(self.ciphersuites),
            "comp_methods": self.comp_methods,
            "extensions": list(map(lambda ext: ext.to_dict(), self.extensions)),
        }

    @classmethod
    def from_dict(cls, d):
        """Unserialize a TLSClientHelloSignature from a dict.

        Parameters
        ----------
        d : dict
            Client Hello signature encoded to a Python dict.

        Returns
        -------
        sig : TLSClientHelloSignature
            Signature constructed based on the dict representation.
        """
        return TLSClientHelloSignature(
            record_version=TLSVersion[d["record_version"]],
            handshake_version=TLSVersion[d["handshake_version"]],
            session_id_length=d["session_id_length"],
            ciphersuites=deserialize_grease(d["ciphersuites"]),
            comp_methods=d["comp_methods"],
            extensions=list(
                map(lambda ext: TLSExtensionSignature.from_dict(ext), d["extensions"])
            ),
        )

    @classmethod
    def from_bytes(cls, record: bytes):
        """Build a TLSClientHelloSignature from a Client Hello TLS record.

        Parameters
        ----------
        record : bytes
            Raw over-the-wire content of the Client Hello TLS record.

        Returns
        -------
        sig : TLSClientHelloSignature
            Signature of the TLS record.
        """
        off = 0
        record_header = TLSRecordHeader._make(
            struct.unpack_from(TLS_RECORD_HEADER, record, off)
        )
        off += struct.calcsize(TLS_RECORD_HEADER)

        if record_header.type != 0x16:
            raise Exception(
                f"TLS record not of type Handshake (0x16). "
                f"Got 0x{record_header.type:02x}"
            )

        if not TLSVersion.has_value(record_header.version):
            raise Exception(f"Unknown TLS version 0x{record_header.version:04x}")

        if len(record) - off != record_header.length:
            raise Exception("Corrupt record length")

        handshake_header = TLSHandshakeHeader._make(
            struct.unpack_from(TLS_HANDSHAKE_HEADER, record, off)
        )

        if handshake_header.type != 0x01:
            raise Exception(
                f"TLS handshake not of type Client Hello (0x01). "
                f"Got 0x{handshake_header.type:02x}"
            )

        if (
            len(record) - off - 4
            != (handshake_header.length_high << 16) + handshake_header.length_low
        ):
            raise Exception("Corrupt handshake length")

        off += struct.calcsize(TLS_HANDSHAKE_HEADER)

        if not TLSVersion.has_value(handshake_header.version):
            raise Exception(f"Unknown TLS version 0x{handshake_header.version:04x}")

        off += handshake_header.session_id_length

        ciphersuites, s = parse_tls_int_list(record[off:], entry_size=2)
        off += s

        comp_methods, s = parse_tls_int_list(
            record[off:], entry_size=1, header_size=1, replace_grease=False
        )
        off += s

        (extensions_length,) = struct.unpack_from("!H", record, off)
        off += struct.calcsize("!H")

        if len(record) - off != extensions_length:
            raise Exception("Corrupt TLS extensions length")

        extensions = []
        while off < len(record):
            _, ext_len = struct.unpack_from(TLS_EXTENSION_HEADER, record, off)
            ext_total_len = ext_len + struct.calcsize(TLS_EXTENSION_HEADER)
            extensions.append(
                TLSExtensionSignature.from_bytes(record[off : off + ext_total_len])
            )
            off += ext_total_len

        return TLSClientHelloSignature(
            record_version=TLSVersion(record_header.version),
            handshake_version=TLSVersion(handshake_header.version),
            session_id_length=handshake_header.session_id_length,
            ciphersuites=ciphersuites,
            comp_methods=comp_methods,
            extensions=extensions,
        )
