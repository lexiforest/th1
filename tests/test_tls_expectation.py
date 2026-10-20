from copy import deepcopy

import pytest

from th1.tls import TLSClientHelloExpectation
from th1.tls.signature import TLSClientHelloSignature

from .test_th1 import CLIENT_HELLO


@pytest.fixture
def signature():
    return TLSClientHelloSignature.from_bytes(CLIENT_HELLO)


def test_partial_top_level_expectation(signature):
    expectation = TLSClientHelloExpectation.from_dict({"session_id_length": 32})
    assert expectation.matches(signature) == (True, "")
    signature.ciphersuites = []
    assert expectation.matches(signature) == (True, "")
    signature.session_id_length = 0
    matched, reason = expectation.matches(signature)
    assert not matched
    assert "tls.session_id_length" in reason


def test_empty_expectation(signature):
    assert TLSClientHelloExpectation.from_dict({}).matches(signature) == (True, "")


@pytest.mark.parametrize("fields", [
    {"session_id_length": 0},
    {"session_id_length": None},
    {"ciphersuites": []},
    {"comp_methods": []},
    {"extensions": []},
])
def test_explicit_values_are_not_wildcards(signature, fields):
    matched, reason = TLSClientHelloExpectation.from_dict(fields).matches(signature)
    assert not matched
    assert f"tls.{next(iter(fields))}" in reason


def test_explicit_empty_list_and_zero_can_match(signature):
    signature.extensions = []
    signature.session_id_length = 0
    expectation = TLSClientHelloExpectation.from_dict({
        "extensions": [], "session_id_length": 0,
    })
    assert expectation.matches(signature) == (True, "")


def test_partial_nested_extension_fields(signature):
    extensions = [{"type": ext.ext_type.name} for ext in signature.extensions]
    index = next(i for i, ext in enumerate(extensions) if ext["type"] == "keyshare")
    extensions[index]["key_shares"] = [{"group": "GREASE"}, {"group": 29}]
    expectation = TLSClientHelloExpectation.from_dict({"extensions": extensions})
    assert expectation.matches(signature) == (True, "")
    signature.extensions[index].key_shares[1]["length"] = 1
    assert expectation.matches(signature) == (True, "")
    signature.extensions[index].key_shares[1]["group"] = 23
    matched, reason = expectation.matches(signature)
    assert not matched
    assert f"extensions[{index}].key_shares[1].group" in reason


@pytest.mark.parametrize("permutation", [False, True])
def test_extension_list_requires_all_entries(signature, permutation):
    extensions = [{"type": ext.ext_type.name} for ext in signature.extensions]
    expectation = TLSClientHelloExpectation.from_dict({"extensions": extensions[:-1]})
    matched, reason = expectation.matches(signature, allow_tls_permutation=permutation)
    assert not matched
    assert "tls.extensions" in reason


def test_permutation_and_fixed_extension_positions(signature):
    extensions = [{"type": ext.ext_type.name} for ext in signature.extensions]
    expectation = TLSClientHelloExpectation.from_dict({"extensions": extensions})
    signature.extensions[1], signature.extensions[2] = (
        signature.extensions[2], signature.extensions[1],
    )
    assert not expectation.matches(signature)[0]
    assert expectation.matches(signature, allow_tls_permutation=True) == (True, "")
    # The first extension is GREASE, which must remain in its original slot.
    signature.extensions[0], signature.extensions[1] = (
        signature.extensions[1], signature.extensions[0],
    )
    assert not expectation.matches(signature, allow_tls_permutation=True)[0]


def test_duplicate_grease_extensions_keep_their_own_fields(signature):
    expectation = TLSClientHelloExpectation.from_dict(signature.to_dict())
    grease = [ext for ext in signature.extensions if ext.ext_type.name == "GREASE"]
    assert len(grease) == 2
    grease[1].length = 9
    matched, reason = expectation.matches(signature, allow_tls_permutation=True)
    assert not matched
    assert ".length" in reason


def test_other_lists_remain_ordered_with_permutation(signature):
    expectation = TLSClientHelloExpectation.from_dict({
        "ciphersuites": signature.to_dict()["ciphersuites"],
    })
    signature.ciphersuites.reverse()
    matched, reason = expectation.matches(signature, allow_tls_permutation=True)
    assert not matched
    assert "tls.ciphersuites[0]" in reason


def test_missing_supplied_nested_field_is_a_mismatch(signature):
    extensions = [{"type": ext.ext_type.name} for ext in signature.extensions]
    extensions[1]["nonexistent"] = None
    matched, reason = TLSClientHelloExpectation.from_dict({
        "extensions": extensions,
    }).matches(signature)
    assert not matched
    assert "extensions[1].nonexistent" in reason


def test_round_trip_and_matching_do_not_mutate_inputs(signature):
    fields = signature.to_dict()
    original = deepcopy(fields)
    expectation = TLSClientHelloExpectation.from_dict(fields)
    fields["extensions"].clear()
    exported = expectation.to_dict()
    exported["ciphersuites"].clear()
    assert expectation.to_dict() == original
    assert expectation.matches(signature, allow_tls_permutation=True) == (True, "")
    assert signature.to_dict() == original


@pytest.mark.parametrize("fields, error", [
    (None, TypeError),
    ({"cipher_suites": []}, ValueError),
    ({"extensions": None}, TypeError),
    ({"extensions": [{}]}, ValueError),
    ({"extensions": [{"type": "unknown"}]}, ValueError),
])
def test_invalid_expectations(fields, error):
    with pytest.raises(error):
        TLSClientHelloExpectation.from_dict(fields)


def test_full_signature_loading_and_equality_remain_strict(signature):
    with pytest.raises(KeyError):
        TLSClientHelloSignature.from_dict({"session_id_length": 32})
    other = TLSClientHelloSignature.from_dict(signature.to_dict())
    other.ciphersuites = []
    assert not signature.equals(other)[0]


def test_explicit_psk_and_padding_are_compared(signature):
    fields = signature.to_dict()
    fields["extensions"] = [
        {"type": "encrypted_client_hello", "length": 0},
        {"type": "padding"},
        {"type": "pre_shared_key", "length": 0},
    ]
    observed = TLSClientHelloSignature.from_dict(fields)
    expectation = TLSClientHelloExpectation.from_dict({"extensions": fields["extensions"]})
    assert expectation.matches(observed) == (True, "")
    observed.extensions.pop()
    assert not expectation.matches(observed)[0]
    observed.extensions.pop()
    assert not expectation.matches(observed)[0]
