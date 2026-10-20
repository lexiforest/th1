"""Explicit, directional expectations for TLS ClientHello signatures."""

from copy import deepcopy

from .extensions import TLSExtensionType
from .signature import TLSClientHelloSignature


def _compare_fields(expected, actual, path):
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False, f"{path}: expected an object, got {actual!r}"
        for key, value in expected.items():
            child_path = f"{path}.{key}"
            if key not in actual:
                return False, f"{child_path}: supplied field is missing"
            matches, reason = _compare_fields(value, actual[key], child_path)
            if not matches:
                return False, reason
    elif isinstance(expected, list):
        if not isinstance(actual, list):
            return False, f"{path}: expected a list, got {actual!r}"
        if len(expected) != len(actual):
            return False, f"{path}: expected {len(expected)} entries, got {len(actual)}"
        for index, (value, observed) in enumerate(zip(expected, actual)):
            matches, reason = _compare_fields(value, observed, f"{path}[{index}]")
            if not matches:
                return False, reason
    elif expected != actual:
        return False, f"{path}: expected {expected!r}, got {actual!r}"
    return True, ""


class TLSClientHelloExpectation:
    """Compare only supplied fields in the serialized TLS signature format.

    Omitted dictionary fields are unconstrained, including fields in extension
    parameters and key shares. Supplied lists describe the complete list and
    are ordered by default. Empty lists and zero values are real expectations.
    An empty dictionary matches any TLSClientHelloSignature.

    Unlike signature equality, explicitly supplied extensions include PSK and
    padding. No extension is silently removed from an expectation or capture.
    """

    _fields = {
        "record_version",
        "handshake_version",
        "session_id_length",
        "ciphersuites",
        "comp_methods",
        "extensions",
    }
    _fixed_extensions = {"GREASE", "pre_shared_key", "padding"}

    def __init__(self, fields: dict):
        if not isinstance(fields, dict):
            raise TypeError("TLS expectation must be a dictionary")
        unknown = fields.keys() - self._fields
        if unknown:
            raise ValueError(f"Unknown TLS expectation fields: {sorted(unknown)}")
        if "extensions" in fields:
            extensions = fields["extensions"]
            if not isinstance(extensions, list):
                raise TypeError("TLS expectation extensions must be a list")
            for index, extension in enumerate(extensions):
                if not isinstance(extension, dict) or "type" not in extension:
                    raise ValueError(f"extensions[{index}] must supply a type")
                if extension["type"] not in TLSExtensionType.__members__:
                    raise ValueError(
                        f"extensions[{index}]: unknown type {extension['type']!r}"
                    )
        self._fields_to_match = deepcopy(fields)

    @classmethod
    def from_dict(cls, fields: dict):
        """Read an expectation without filling in omitted signature fields."""
        return cls(fields)

    def to_dict(self):
        """Return an independent copy containing exactly the supplied fields."""
        return deepcopy(self._fields_to_match)

    def matches(
        self, signature: TLSClientHelloSignature, allow_tls_permutation: bool = False
    ) -> tuple[bool, str]:
        """Return (matched, reason), with a field path on mismatch.

        With permutation enabled, ordinary extensions may change order. GREASE,
        PSK, and padding retain their positions. Other lists remain ordered.
        """
        if not isinstance(signature, TLSClientHelloSignature):
            raise TypeError("Expected a TLSClientHelloSignature to match against")
        expected = self.to_dict()
        actual = signature.to_dict()
        if allow_tls_permutation and "extensions" in expected:
            extensions = expected.pop("extensions")
            observed = actual["extensions"]
            if len(extensions) != len(observed):
                return False, (
                    f"tls.extensions: expected {len(extensions)} entries, "
                    f"got {len(observed)}"
                )
            used = set()
            for index, extension in enumerate(extensions):
                ext_type = extension["type"]
                if ext_type in self._fixed_extensions:
                    target = index
                else:
                    target = next(
                        (
                            i for i, ext in enumerate(observed)
                            if i not in used and ext["type"] == ext_type
                        ),
                        None,
                    )
                    if target is None:
                        return False, (
                            f"tls.extensions[{index}].type: "
                            f"expected {ext_type!r}, no matching extension"
                        )
                matches, reason = _compare_fields(
                    extension, observed[target], f"tls.extensions[{index}]"
                )
                if not matches:
                    return False, reason
                used.add(target)
        return _compare_fields(expected, actual, "tls")
