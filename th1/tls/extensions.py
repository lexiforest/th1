import enum
import struct
from typing import List, Optional

from ..base import Signature
from .utils import (
    TLS_EXTENSION_HEADER,
    TLS_GREASE,
    TLS_GREASE_VALUES,
    TLSExtensionHeader,
    TLSVersion,
    deserialize_grease,
    parse_tls_int_list,
    parse_tls_str_list,
    serialize_grease,
)


class TLSExtensionType(enum.IntEnum):
    # TLS extensions list
    # See https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    # for the official list, and
    # https://github.com/google/boringssl/blob/master/include/openssl/tls1.h
    # for BoringSSL's list of supported extensions
    server_name = 0
    status_request = 5
    supported_groups = 10
    ec_point_formats = 11
    signature_algorithms = 13
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    padding = 21
    encrypt_then_mac = 22
    extended_master_secret = 23
    compress_certificate = 27
    record_size_limit = 28
    delegated_credentials = 34
    session_ticket = 35
    pre_shared_key = 41
    supported_versions = 43
    psk_key_exchange_modes = 45
    post_handshake_auth = 49
    keyshare = 51
    # See https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html
    next_protocol_negotiation = 13172
    application_settings = 17513
    application_settings_new = 17613
    renegotiation_info = 65281
    encrypted_client_hello = 0xFE0D
    ech_outer_extensions = 0xFD00

    # Special value to denote a GREASE extension.
    GREASE = TLS_GREASE


class TLSExtensionSignature(Signature):
    """
    Signature of a TLS extension.

    Used to check if two TLS extensions are configured similarly.

    For TLS extensions that have internal parameters to be checked,
    a subclass should be created. Subclasses should implement to_dict(),
    from_dict() and from_bytes() classmethods. See the subclasses below.
    """

    # A registry of subclasses
    registry = {}
    ext_type: TLSExtensionType

    def __init__(self, length: Optional[int] = None):
        self.length = length

    def __init_subclass__(cls, ext_type: TLSExtensionType, **kwargs):
        """Register subclasses to the registry"""
        super().__init_subclass__(**kwargs)
        cls.registry[ext_type] = cls
        cls.ext_type = ext_type

    def to_dict(self):
        """Serialize to a dict object.

        By default we serialize the type and length only.
        To serialize additional parameters, override this in a subclass.
        """
        d: dict[str, str | int | list] = {"type": self.ext_type.name}
        if self.length is not None:
            d["length"] = self.length
        return d

    def equals(self, other: "TLSExtensionSignature"):
        # To check equality, we just compare the dict serializations.
        return self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, d):
        """Deserialize a TLSExtensionSignature from a dict.

        Initializes the suitable subclass if exists, otherwise initializes
        a TLSExtensionSignature proper instance.
        """
        d = d.copy()
        ext_type = TLSExtensionType[d.pop("type")]
        if ext_type not in cls.registry:
            print(cls.registry)
            raise Exception(f"Extension type {ext_type} unknown.")
        return cls.registry[ext_type].from_dict(d)

    @classmethod
    def from_bytes(cls, ext: bytes):
        """Build a TLSExtensionSignature from a raw TLS extension.

        Parameters
        ----------
        ext : bytes
            Raw over-the-wire contents of the TLS extension.
        """
        off = 0
        header = TLSExtensionHeader._make(
            struct.unpack_from(TLS_EXTENSION_HEADER, ext, off)
        )
        off += struct.calcsize(TLS_EXTENSION_HEADER)
        if header.type in TLS_GREASE_VALUES:
            ext_type = TLSExtensionType.GREASE
        else:
            ext_type = TLSExtensionType(header.type)

        if ext_type not in cls.registry:
            raise Exception(f"Extension type {ext_type} unknown.")

        return cls.registry[ext_type].from_bytes(
            length=header.length, data=ext[off : off + header.length]
        )


class TLSExtensionGrease(TLSExtensionSignature, ext_type=TLSExtensionType.GREASE):
    def __init__(self, length, data=None):
        super().__init__(length)
        self.data = data

    def to_dict(self):
        # Add the binary data to the serialization.
        d = super().to_dict()
        if self.data:
            d["data"] = self.data
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(d["length"], d.get("data"))

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length, data)


class TLSExtensionExtendedMasterSecret(
    TLSExtensionSignature, ext_type=TLSExtensionType.extended_master_secret
):
    def __init__(self, length):
        super().__init__(length)

    @classmethod
    def from_dict(cls, d):
        return cls(d["length"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionRenegotiationInfo(
    TLSExtensionSignature, ext_type=TLSExtensionType.renegotiation_info
):
    def __init__(self, length):
        super().__init__(length)

    @classmethod
    def from_dict(cls, d):
        return cls(d["length"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionSignedCertificateTimestamp(
    TLSExtensionSignature, ext_type=TLSExtensionType.signed_certificate_timestamp
):
    def __init__(self, length):
        super().__init__(length)

    @classmethod
    def from_dict(cls, d):
        return cls(d["length"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionSessionTicket(
    TLSExtensionSignature, ext_type=TLSExtensionType.session_ticket
):
    def __init__(self, length):
        super().__init__(length)

    @classmethod
    def from_dict(cls, d):
        return cls(d["length"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionServerName(
    TLSExtensionSignature, ext_type=TLSExtensionType.server_name
):
    def __init__(self):
        # Set length to None. Server names have differing lengths,
        # so the length should not be part of the signature.
        super().__init__(length=None)

    @classmethod
    def from_dict(cls, d):
        return cls()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls()


class TLSExtensionStatusRequest(
    TLSExtensionSignature, ext_type=TLSExtensionType.status_request
):
    def __init__(self, length, status_request_type: int):
        super().__init__(length=length)
        self.status_request_type = status_request_type

    def to_dict(self):
        d = super().to_dict()
        d["status_request_type"] = self.status_request_type
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (status_request_type,) = struct.unpack_from("!B", data, 0)
        return cls(length, status_request_type)


class TLSExtensionSupportedGroups(
    TLSExtensionSignature, ext_type=TLSExtensionType.supported_groups
):
    def __init__(self, length, supported_groups: List[int]):
        super().__init__(length)
        self.supported_groups = supported_groups

    def to_dict(self):
        d = super().to_dict()
        d["supported_groups"] = serialize_grease(self.supported_groups)
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(
            length=d["length"],
            supported_groups=deserialize_grease(d["supported_groups"]),
        )

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        groups, _ = parse_tls_int_list(data, entry_size=2)
        return cls(length, groups)


class TLSExtensionECPointFormats(
    TLSExtensionSignature, ext_type=TLSExtensionType.ec_point_formats
):
    def __init__(self, length, ec_point_formats: List[int]):
        super().__init__(length)
        self.ec_point_formats = ec_point_formats

    def to_dict(self):
        d = super().to_dict()
        d["ec_point_formats"] = self.ec_point_formats
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        ec_point_formats, _ = parse_tls_int_list(data, entry_size=1, header_size=1)
        return TLSExtensionECPointFormats(length, ec_point_formats)


class TLSExtensionSignatureAlgorithms(
    TLSExtensionSignature, ext_type=TLSExtensionType.signature_algorithms
):
    def __init__(self, length, sig_hash_algs: List[int]):
        super().__init__(length=length)
        self.sig_hash_algs = sig_hash_algs

    def to_dict(self):
        d = super().to_dict()
        d["sig_hash_algs"] = self.sig_hash_algs
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        sig_hash_algs, _ = parse_tls_int_list(data, entry_size=2)
        return cls(length, sig_hash_algs)


class TLSExtensionALPN(
    TLSExtensionSignature,
    ext_type=TLSExtensionType.application_layer_protocol_negotiation,
):
    def __init__(self, length, alpn_list: List[str]):
        super().__init__(length=length)
        self.alpn_list = alpn_list

    def to_dict(self):
        d = super().to_dict()
        d["alpn_list"] = self.alpn_list
        return d

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionALPN(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        alpn_list, _ = parse_tls_str_list(data)
        return TLSExtensionALPN(length, alpn_list)


class TLSExtensionPadding(TLSExtensionSignature, ext_type=TLSExtensionType.padding):
    def __init__(self):
        # Padding has varying lengths, so don't include in the signature
        super().__init__(length=None)

    @classmethod
    def from_dict(cls, d):
        return cls()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls()


class TLSExtensionEncryptThenMAC(
    TLSExtensionSignature, ext_type=TLSExtensionType.encrypt_then_mac
):
    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionCompressCertificate(
    TLSExtensionSignature, ext_type=TLSExtensionType.compress_certificate
):
    def __init__(self, length, algorithms):
        super().__init__(length=length)
        self.algorithms = algorithms

    def to_dict(self):
        d = super().to_dict()
        d["algorithms"] = self.algorithms
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        algos, _ = parse_tls_int_list(data, entry_size=2, header_size=1)
        return cls(length, algos)


class TLSExtensionRecordSizeLimit(
    TLSExtensionSignature, ext_type=TLSExtensionType.record_size_limit
):
    def __init__(self, length, record_size_limit):
        super().__init__(length=length)
        self.record_size_limit = record_size_limit

    def to_dict(self):
        d = super().to_dict()
        d["record_size_limit"] = self.record_size_limit
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (limit,) = struct.unpack("!H", data)
        return cls(length, limit)


class TLSExtensionDelegatedCredentials(
    TLSExtensionSignature, ext_type=TLSExtensionType.delegated_credentials
):
    def __init__(self, length, sig_hash_algs):
        super().__init__(length=length)
        self.sig_hash_algs = sig_hash_algs

    def to_dict(self):
        d = super().to_dict()
        d["sig_hash_algs"] = self.sig_hash_algs
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        algs, _ = parse_tls_int_list(data, entry_size=2)
        return cls(length, algs)


class TLSExtensionSupportedVersions(
    TLSExtensionSignature, ext_type=TLSExtensionType.supported_versions
):
    def __init__(self, length, supported_versions: List[TLSVersion]):
        super().__init__(length=length)
        self.supported_versions = supported_versions

    def to_dict(self):
        d = super().to_dict()
        d["supported_versions"] = list(map(lambda v: v.name, self.supported_versions))
        return d

    @classmethod
    def from_dict(cls, d):
        supported_versions = list(map(lambda v: TLSVersion[v], d["supported_versions"]))
        return TLSExtensionSupportedVersions(d["length"], supported_versions)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        versions, _ = parse_tls_int_list(data, entry_size=2, header_size=1)
        versions = list(map(lambda v: TLSVersion(v), versions))
        return TLSExtensionSupportedVersions(length, versions)


class TLSExtensionPSKKeyExchangeModes(
    TLSExtensionSignature, ext_type=TLSExtensionType.psk_key_exchange_modes
):
    def __init__(self, length, psk_ke_mode):
        super().__init__(length=length)
        self.psk_ke_mode = psk_ke_mode

    def to_dict(self):
        d = super().to_dict()
        d["psk_ke_mode"] = self.psk_ke_mode
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (ke_length, ke_mode) = struct.unpack_from("!BB", data, 0)
        if ke_length > 1:
            # Unsupported
            raise Exception("Failed to parse psk_key_exchange_modes extension")

        return cls(length, ke_mode)


class TLSExtensionPostHandshakeAuth(
    TLSExtensionSignature, ext_type=TLSExtensionType.post_handshake_auth
):
    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionKeyshare(TLSExtensionSignature, ext_type=TLSExtensionType.keyshare):
    def __init__(self, length, key_shares):
        super().__init__(length=length)
        self.key_shares = key_shares

    def to_dict(self):
        d = super().to_dict()
        d["key_shares"] = [
            {
                "group": ("GREASE" if ks["group"] == TLS_GREASE else ks["group"]),
                "length": ks["length"],
            }
            for ks in self.key_shares
        ]
        return d

    @classmethod
    def from_dict(cls, d):
        d["key_shares"] = [
            {
                "group": (TLS_GREASE if ks["group"] == "GREASE" else ks["group"]),
                "length": ks["length"],
            }
            for ks in d["key_shares"]
        ]
        return TLSExtensionKeyshare(d["length"], d["key_shares"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        off = 0
        (key_share_length,) = struct.unpack_from("!H", data, off)
        off += struct.calcsize("!H")

        key_shares = []
        while off < length:
            (group, key_ex_length) = struct.unpack_from("!HH", data, off)
            key_shares.append(
                {
                    "group": TLS_GREASE if group in TLS_GREASE_VALUES else group,
                    "length": key_ex_length,
                }
            )
            off += struct.calcsize("!HH")
            off += key_ex_length

        return TLSExtensionKeyshare(length, key_shares)


class TLSExtensionNextProtocolNegotiation(
    TLSExtensionSignature, ext_type=TLSExtensionType.next_protocol_negotiation
):
    def __init__(self, length):
        super().__init__(length=length)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length)


class TLSExtensionApplicationSettings(
    TLSExtensionSignature, ext_type=TLSExtensionType.application_settings
):
    def __init__(self, length, alps_alpn_list):
        super().__init__(length=length)
        self.alps_alpn_list = alps_alpn_list

    def to_dict(self):
        d = super().to_dict()
        d["alps_alpn_list"] = self.alps_alpn_list
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        alpn, _ = parse_tls_str_list(data)
        return cls(length, alpn)


class TLSExtensionApplicationSettingsNew(
    TLSExtensionSignature, ext_type=TLSExtensionType.application_settings_new
):
    def __init__(self, length, alps_alpn_list):
        super().__init__(length=length)
        self.alps_alpn_list = alps_alpn_list

    def to_dict(self):
        d = super().to_dict()
        d["alps_alpn_list"] = self.alps_alpn_list
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        alpn, _ = parse_tls_str_list(data)
        return cls(length, alpn)


class TLSExtensionGrease(
    TLSExtensionSignature, ext_type=TLSExtensionType.encrypted_client_hello
):
    def __init__(self, length=0, data=None):
        super().__init__(length)
        self.data = data

    def to_dict(self):
        # Add the binary data to the serialization.
        d = super().to_dict()
        return d

    @classmethod
    def from_dict(cls, d):
        return cls()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length=0, data=None)


class TLSExtensionPreSharedKey(
    TLSExtensionSignature, ext_type=TLSExtensionType.pre_shared_key
):
    def __init__(self, length=0, data=None):
        super().__init__(length)
        self.data = data

    def to_dict(self):
        # Add the binary data to the serialization.
        d = super().to_dict()
        return d

    @classmethod
    def from_dict(cls, d):
        return cls()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return cls(length=0, data=None)
