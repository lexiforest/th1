import struct

import pytest

from th1.tls.extensions import (
    TLSExtensionSignature,
    TLSExtensionTrustAnchors,
    TLSExtensionType,
)
from th1.tls.signature import TLSClientHelloSignature


@pytest.mark.parametrize("payload", [b"\x00\x00", b"\x00\x05\x02\x81\x01\x01\x02"])
def test_trust_anchors_parsing_and_serialization(payload):
    extension = struct.pack("!HH", 51764, len(payload)) + payload
    signature = TLSExtensionSignature.from_bytes(extension)

    assert isinstance(signature, TLSExtensionTrustAnchors)
    assert signature.ext_type == TLSExtensionType.trust_anchors
    expected = {"type": "trust_anchors", "length": len(payload)}
    assert signature.to_dict() == expected
    restored = TLSExtensionSignature.from_dict(expected)
    assert isinstance(restored, TLSExtensionTrustAnchors)
    assert restored.equals(signature)


def test_client_hello_with_trust_anchors():
    # A minimal ClientHello with an empty trust anchor list and an extension
    # after it, ensuring parsing continues at the correct offset.
    extensions = bytes.fromhex("ca34 0002 0000 0017 0000")
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + bytes.fromhex("0002 1301 0100")
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake

    signature = TLSClientHelloSignature.from_bytes(record)
    serialized = signature.to_dict()
    assert serialized["extensions"] == [
        {"type": "trust_anchors", "length": 2},
        {"type": "extended_master_secret", "length": 0},
    ]
    restored = TLSClientHelloSignature.from_dict(serialized)
    equal, reason = signature.equals(restored)
    assert equal, reason

    restored.extensions.pop(0)
    equal, _ = signature.equals(restored)
    assert not equal
