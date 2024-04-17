from typing import Optional

from .http2.signature import HTTP2Signature
from .tls.signature import TLSClientHelloSignature


class BrowserSignature:
    """
    Represents the network signature of a specific browser based on multiple
    network parameters.

    Attributes
    ----------
    tls_client_hello : TLSClientHelloSignature
        The signature of the browser's TLS Client Hello message.
        Can be None, in which case it is ignored.
    http2 : HTTP2Signature
        The HTTP/2 signature of the browser.
        Can be None, in which case it is ignored.
    options: dict
        Optional parameters specifying how to
    """

    def __init__(
        self,
        tls_client_hello: TLSClientHelloSignature,
        http2: HTTP2Signature,
        options: Optional[dict] = None,
    ):
        self.tls_client_hello = tls_client_hello
        self.http2 = http2
        self.options = options

    def __eq__(self, other: "BrowserSignature"):
        if self.tls_client_hello != other.tls_client_hello:
            return False
        if self.http2 != other.http2:
            print("http2 diff")
            return False
        return True

    def to_dict(self) -> dict:
        """Serialize to a dict object."""
        ret = {
            "tls_client_hello": self.tls_client_hello.to_dict() or {},
            "http2": self.http2.to_dict() or {},
        }
        if self.options:
            ret["options"] = self.options
        return ret

    @classmethod
    def from_dict(cls, d):
        """Deserialize a BrowserSignature from a dict."""
        tls_client_hello = TLSClientHelloSignature.from_dict(d.get("tls_client_hello"))
        http2 = HTTP2Signature.from_dict(d.get("http2"))
        options = d.get("options", {})
        tls_client_hello.allow_ext_permutation = options.get(
            "tls_permute_extensions", False
        )

        return cls(
            tls_client_hello=tls_client_hello, http2=http2, options=d.get("options")
        )
