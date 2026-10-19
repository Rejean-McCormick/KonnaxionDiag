"""Strict PEP contract / no installation or deployment side effects."""
import json
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assurance.pep import verify_activation_admission
from assurance.release_set import _sha256_json
from diagcore.signing import sign_payload
from diagcore.cli import main


def _keys(path):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives import serialization
    secret = crypto.Ed25519PrivateKey.generate()
    priv, pub = path / "issuer.pem", path / "issuer.pub"
    priv.write_bytes(secret.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub.write_bytes(secret.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def _sample(path):
    priv, pub = _keys(path)
    now = datetime.now(timezone.utc)
    dg = lambda char: "sha256:" + char * 64
    identity = {
        "schema": "konnaxiondiag.release-set.identity.v1",
        "source_commit_sha": "a" * 40,
        "source_tree_digest": "git-sha1:" + "b" * 40,
        "capsule_digest": dg("c"), "capsule_digests": [dg("c")],
        "image_digests": [dg("d")], "runtime_pack_digest": dg("e"),
        "policy_bundle_digest": dg("f"), "infra_manifest_digest": dg("0"),
        "sbom_digest": dg("1"), "provenance_digest": dg("2"),
    }
    digest = _sha256_json(identity)
    release = {
        "schema": "konnaxiondiag.release-set.v1", "identity": identity,
        "release_set_digest": digest, "security_evidence_set_digest": dg("3"),
        "required_components": ["source", "capsule", "images", "runtime_pack", "policy_bundle", "infra_manifest", "sbom", "provenance"],
        "complete": True, "problems": [],
        "qualification_policy_digest": dg("4"),
        "security_contract_registry_digest": dg("5"),
    }
    verdict = {
        "schema": "konnaxiondiag.release-verdict.v5", "run_id": "run42", "verdict": "PASS",
        "authorization": {"schema": "konnaxiondiag.release-authorization.v1", "subject": digest, "verdict": "PASS", "policy_version": "policy-v1", "issued_at": (now - timedelta(minutes=2)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(), "run_id": "run42", "nonce": "0123456789abcdefghijkl"},
        "release_set": deepcopy(release),
        "subject_binding": {"required": True, "valid": True, "release_set_digest": digest},
        "security": {"clean": True, "s14_verdict": "PASS"},
        "functional": {"clean": True}, "target_protection": {"verdict": "PASS"},
        "signature": {"status": "SIGNED"}, "consumer_contract": {"caller_may_disable_gate": False},
    }
    return priv, pub, release, verdict, sign_payload(verdict, priv)


def _check(pub, release, verdict, signature, *, measured=None, policy="policy-v1"):
    return verify_activation_admission(
        verdict, signature, trusted_public_keys=[pub], active_release_set=release,
        measured_release_set_digest=measured if measured is not None else release["release_set_digest"],
        expected_policy_version=policy,
    )


def test_exact_trusted_release_admitted():
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw); _, pub, release, verdict, signature = _sample(path)
        ok, detail = _check(pub, release, verdict, signature)
        assert ok, detail
        assert detail["problems"] == []


@pytest.mark.parametrize("change,marker", [
    ("measured", "Agent-measured"),
    ("policy", "policy_version mismatch"),
    ("key", "not trusted/valid"),
    ("tampered_verdict", "not trusted/valid"),
    ("invalid_schema", "unsupported release signature envelope"),
    ("wrong_purpose", "release signature purpose mismatch"),
    ("wrong_algorithm", "release signature algorithm mismatch"),
    ("spoofed_key_fingerprint", "fingerprint does not match"),
    ("missing_policy_digest", "qualification_policy_digest is not a valid digest"),
    ("expired", "authorization has expired"),
    ("unsigned", "not trusted/valid"),
    ("altered_active", "signed ReleaseSet differs"),
    ("missing_component", "production ReleaseSet component missing"),
    ("weak_policy", "production ReleaseSet required component policy is incomplete"),
    ("incomplete", "incomplete or contains unresolved"),
    ("not_clean", "security qualification"),
    ("wrong_run", "run ID differs"),
    ("bypass", "prohibit caller bypass"),
    ("bad_subject", "subject binding digest mismatch"),
    ("not_pass", "not activation-acceptable"),
])
def test_strict_pep_rejects(change, marker):
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw); priv, pub, release, verdict, signature = _sample(path)
        kw = {}
        if change == "measured": kw["measured"] = "sha256:" + "f" * 64
        if change == "policy": kw["policy"] = "policy-v2"
        if change == "key":
            other_priv, other_pub = _keys(path)
            pub = other_pub
        if change == "tampered_verdict": verdict["security"]["clean"] = False
        if change == "invalid_schema": signature["schema"] = "unsupported.signature"
        if change == "wrong_purpose": signature["purpose"] = "other-purpose"
        if change == "wrong_algorithm": signature["algorithm"] = "rsa"
        if change == "spoofed_key_fingerprint": signature["public_key_fingerprint_sha256"] = "d" * 64
        if change == "missing_policy_digest":
            release.pop("qualification_policy_digest")
            verdict["release_set"] = deepcopy(release)
            signature = sign_payload(verdict, priv)
        if change == "expired":
            verdict["authorization"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            signature = sign_payload(verdict, priv)
        if change == "unsigned": signature["signature_base64"] = "AAAA"
        if change == "altered_active": release["security_evidence_set_digest"] = "sha256:" + "a" * 64
        if change == "missing_component":
            release["identity"]["sbom_digest"] = None
            release["release_set_digest"] = _sha256_json(release["identity"])
            verdict["release_set"] = deepcopy(release)
            verdict["authorization"]["subject"] = release["release_set_digest"]
            verdict["subject_binding"]["release_set_digest"] = release["release_set_digest"]
            signature = sign_payload(verdict, priv)
        if change == "weak_policy":
            release["required_components"] = ["source"]
            verdict["release_set"] = deepcopy(release)
            signature = sign_payload(verdict, priv)
        if change == "incomplete":
            release["problems"] = ["missing files"]
            verdict["release_set"] = deepcopy(release)
            signature = sign_payload(verdict, priv)
        if change == "not_clean":
            verdict["security"]["clean"] = False
            signature = sign_payload(verdict, priv)
        if change == "wrong_run":
            verdict["run_id"] = "other-run"
            signature = sign_payload(verdict, priv)
        if change == "bypass":
            verdict["consumer_contract"]["caller_may_disable_gate"] = True
            signature = sign_payload(verdict, priv)
        if change == "bad_subject":
            verdict["subject_binding"]["release_set_digest"] = "sha256:" + "a" * 64
            signature = sign_payload(verdict, priv)
        if change == "not_pass":
            verdict["verdict"] = "WARN"; verdict["authorization"]["verdict"] = "WARN"
            signature = sign_payload(verdict, priv)
        ok, details = _check(pub, release, verdict, signature, **kw)
        assert not ok, (change, details)
        assert any(marker in problem for problem in details["problems"]), (change, details)


def test_empty_trust_policy_and_measurement_denied():
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw); _, pub, rs, verdict, sig = _sample(path)
        ok, detail = verify_activation_admission(verdict, sig, trusted_public_keys=[], active_release_set=rs, measured_release_set_digest="", expected_policy_version="")
        assert not ok
        assert any("no trusted" in p for p in detail["problems"])
        assert any("policy version is required" in p for p in detail["problems"])


def test_verify_activation_cli_exit_codes(tmp_path, capsys):
    priv, pub, rs, verdict, sig = _sample(tmp_path)
    files = [tmp_path / name for name in ("verdict.json", "signature.json", "release_set.json")]
    for file, value in zip(files, (verdict, sig, rs)):
        file.write_text(json.dumps(value), encoding="utf-8")
    base = ["verify-activation", *map(str, files), "--public-key", str(pub), "--policy-version", "policy-v1", "--measured-digest", rs["release_set_digest"]]
    assert main(base) == 0
    assert "ADMIT" in capsys.readouterr().out
    base[-1] = "sha256:" + "e" * 64
    assert main(base) == 20
    assert "DENY" in capsys.readouterr().out
