from pathlib import Path

import pytest
import yaml

from th1.browser import BrowserSignature
from th1.http2.frames import HTTP2SettingsFrame
from th1.http2.parser import parse_nghttpd_log
from th1.http2.signature import HTTP2Signature
from th1.tls.extensions import TLSExtensionPadding, TLSExtensionType
from th1.tls.signature import TLSClientHelloSignature


@pytest.fixture
def browser_signatures():
    docs = {}
    for path in Path("signatures").glob("**/*.yaml"):
        with open(path, "r") as f:
            # Parse signatures.yaml database.
            for doc in yaml.safe_load_all(f.read()):
                if not doc:
                    continue
                name = "_".join(
                    [
                        doc["browser"]["name"],
                        str(doc["browser"]["version"]),
                        doc["browser"]["os"],
                    ]
                )
                docs[name] = doc
    return docs


"""Test the signature.py module.

signature.py is responsible for decoding signatures from the YAML format,
parsing raw TLS packets, and comparing signatures.
"""

# Client Hello record sent by Chrome 98.
CLIENT_HELLO = (
    b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x06\x84\xbd\x63\xac"
    b"\xa4\x0a\x5b\xbe\x79\x7d\x14\x48\xcc\x1f\xf8\x62\x8c\x7d\xf4\xc7"
    b"\xfe\x04\xe3\x30\xb7\x56\xec\x87\x40\xf2\x63\x20\x92\x9d\x01\xc8"
    b"\x82\x3c\x92\xe1\x8a\x75\x4e\xaa\x6b\xf1\x31\xd2\xb7\x4d\x18\xc6"
    b"\xda\x3d\x31\xa6\x35\xb2\x08\xbc\x5b\x82\x2f\x97\x00\x20\x9a\x9a"
    b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
    b"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00"
    b"\x01\x93\xca\xca\x00\x00\x00\x00\x00\x16\x00\x14\x00\x00\x11\x77"
    b"\x77\x77\x2e\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x2e\x6f\x72\x67"
    b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08\xaa"
    b"\xaa\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00"
    b"\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f"
    b"\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x12"
    b"\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06"
    b"\x06\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29\xaa\xaa\x00\x01"
    b"\x00\x00\x1d\x00\x20\xfc\x58\xaa\x8b\xd6\x2d\x65\x9c\x58\xa2\xc9"
    b"\x0c\x5a\x6f\x69\xa5\xef\xc0\x05\xb3\xd1\xb4\x01\x9d\x61\x84\x00"
    b"\x42\x74\xc7\xa9\x43\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x07\x06"
    b"\xaa\xaa\x03\x04\x03\x03\x00\x1b\x00\x03\x02\x00\x02\x44\x69\x00"
    b"\x05\x00\x03\x02\x68\x32\xfa\xfa\x00\x01\x00\x00\x15\x00\xc6\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00"
)


def test_tls_signature_serialization(browser_signatures):
    """
    Test that deserializing and then serializing the YAML signatures
    produces identical results.
    """
    for name, data in browser_signatures.items():
        sig = data["signature"]

        # parse and serialize back.
        sig2 = BrowserSignature.from_dict(sig).to_dict()

        # Go extension by extension and check equality.
        # It could be done with a single comparison, but this way the error
        # will be more indicative.
        for i, ext in enumerate(sig["tls_client_hello"]["extensions"]):
            assert ext == sig2["tls_client_hello"]["extensions"][i]
        assert sig == sig2, name


def test_tls_client_hello_parsing(browser_signatures):
    """
    Test the TLS Client Hello parsing code.
    """
    sig = TLSClientHelloSignature.from_bytes(CLIENT_HELLO)
    sig2 = TLSClientHelloSignature.from_dict(
        browser_signatures["chrome_98.0.4758.102_win10"]["signature"][
            "tls_client_hello"
        ]
    )

    equal, reason = sig.equals(sig2)
    assert equal, reason


def test_tls_client_hello_equalities_with_permutation(browser_signatures):
    for name, data in browser_signatures.items():
        sig = TLSClientHelloSignature.from_dict(data["signature"]["tls_client_hello"])
        sig2 = TLSClientHelloSignature.from_dict(data["signature"]["tls_client_hello"])
        if data["signature"].get("options", {}).get("tls_permute_extensions"):
            allow_tls_permutation = True
            sig2.permuate()
        else:
            allow_tls_permutation = False
        equal, reason = sig.equals(sig2, allow_tls_permutation=allow_tls_permutation)
        assert equal, reason


def test_tls_client_hello_ignore_psk(browser_signatures):
    chrome119 = browser_signatures["chrome_119.0.6045.199_macOS"]
    hello_dict = chrome119["signature"]["tls_client_hello"]

    sig = TLSClientHelloSignature.from_dict(hello_dict)
    sig_without_psk = TLSClientHelloSignature.from_dict(hello_dict)
    sig_without_psk.extensions.pop()  # Per the RFC, PSK must be the last one

    equals, reason = sig.equals(sig_without_psk)
    assert equals, reason


def test_tls_client_hello_ignore_padding_with_ech(browser_signatures):
    chrome119 = browser_signatures["chrome_119.0.6045.199_macOS"]
    hello_dict = chrome119["signature"]["tls_client_hello"]

    sig = TLSClientHelloSignature.from_dict(hello_dict)
    sig_with_padding = TLSClientHelloSignature.from_dict(hello_dict)
    sig_with_padding.extensions.append(TLSExtensionPadding())

    has_ech = any([ext.ext_type == TLSExtensionType.encrypted_client_hello for ext in sig.extensions])
    assert has_ech

    equals, reason = sig.equals(sig_with_padding)
    assert equals, reason


def test_nghttpd_log_serialization(browser_signatures):
    for name, data in browser_signatures.items():
        sig = data["signature"]

        # Deserialize and serialize back.
        sig2 = BrowserSignature.from_dict(sig).to_dict()

        # Go extension by extension and check equality.
        # It could be done with a single comparison, but this way the error
        # will be more indicative.
        for i, ext in enumerate(sig["http2"]["frames"]):
            assert ext == sig2["http2"]["frames"][i]
        assert sig == sig2, name


def test_nghttpd_log_parsing(browser_signatures):
    sig = parse_nghttpd_log(open("logs/chrome-119.log", "rb").read())
    sig2 = HTTP2Signature.from_dict(
        browser_signatures["chrome_119.0.6045.199_macOS"]["signature"]["http2"]
    )
    equal, reason = sig.equals(sig2)
    assert equal, reason


def test_http2_equalities(browser_signatures):
    for name, data in browser_signatures.items():
        sig = HTTP2Signature.from_dict(data["signature"]["http2"])
        sig2 = HTTP2Signature.from_dict(data["signature"]["http2"])
        equal, reason = sig.equals(sig2)
        assert equal, reason


def test_http2_equalities_with_empty_settings_frame(browser_signatures):
    chrome119 = browser_signatures["chrome_119.0.6045.199_macOS"]
    sig = HTTP2Signature.from_dict(chrome119["signature"]["http2"])
    sig_with_empty_settings = HTTP2Signature.from_dict(chrome119["signature"]["http2"])
    sig_with_empty_settings.frames.append(HTTP2SettingsFrame(0, []))
    equal, reason = sig.equals(sig_with_empty_settings)
    assert equal, reason


def test_nghttpd_log_equalities_with_only_headers(browser_signatures):
    """
    Make sure that it works with legacy signatures that only contains the headers frame.
    """
    sig1 = HTTP2Signature.from_dict(
        browser_signatures["chrome_118.0.5993.117_linux"]["signature"]["http2"]
    )
    sig2 = HTTP2Signature.from_dict(
        browser_signatures["chrome_118.0.5993.117_linux"]["signature"]["http2"]
    )
    sig2.frames = [f for f in sig2.frames if f.frame_type == "HEADERS"]
    equal, reason = sig1.equals(sig2)
    assert equal, reason
