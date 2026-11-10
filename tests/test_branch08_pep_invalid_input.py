"""Branch 08: malformed PEP documents deny explicitly without an exception."""
from __future__ import annotations

import pytest

from assurance.pep import verify_activation_admission, verify_release_authorization


@pytest.mark.parametrize("verdict,signature,release", [
    (None, {}, {}), ({}, None, {}), ({}, {}, None),
    ([], {}, {}), ({}, [], {}), ({}, {}, []),
])
def test_malformed_direct_authorization_always_returns_denial(verdict, signature, release):
    ok, detail = verify_release_authorization(
        verdict, signature, trusted_public_keys=[], active_release_set=release,
    )
    assert ok is False
    assert detail["problems"]


@pytest.mark.parametrize("verdict,release", [(None, {}), ({}, None), ([], {}), ({}, [])])
def test_malformed_activation_input_always_returns_denial(verdict, release):
    ok, detail = verify_activation_admission(
        verdict, {}, trusted_public_keys=[], active_release_set=release,
        measured_release_set_digest="", expected_policy_version="",
    )
    assert ok is False
    assert detail["problems"]
