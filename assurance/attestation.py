from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from diagcore.assurance import temporal_attestation_check, verify_signed_attestation

ATTESTATION_SCHEMA = "konnaxiondiag.attestation.v1"
PURPOSE_PREFIX = "konnaxiondiag-attestation:"
SHA256_RX = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")


def attestation_purpose(evidence_type: str) -> str:
    et = str(evidence_type or "").strip()
    if not et or any(ch in et for ch in "\r\n\x00"):
        raise ValueError("evidence_type is missing or unsafe")
    return PURPOSE_PREFIX + et


def _digest_ok(value: Any) -> bool:
    return bool(SHA256_RX.fullmatch(str(value or "").strip()))


def validate_universal_attestation(
    payload: dict[str, Any],
    envelope: dict[str, Any] | None,
    *,
    public_keys: Iterable[Path],
    expected_release_set_digest: str,
    expected_evidence_type: str | None = None,
    expected_issuers: Iterable[str] | None = None,
    expected_policy_digest: str | None = None,
    expected_nonce: str | None = None,
    max_age_seconds: int | None = 86400,
    signature_required: bool = True,
) -> tuple[bool, dict[str, Any]]:
    problems: list[str] = []
    if payload.get("schema") != ATTESTATION_SCHEMA:
        problems.append("invalid attestation schema")
    evidence_type = str(payload.get("evidence_type", "")).strip()
    if not evidence_type:
        problems.append("evidence_type missing")
    if expected_evidence_type and evidence_type != expected_evidence_type:
        problems.append("evidence_type mismatch")
    issuer = str(payload.get("issuer", "")).strip()
    if not issuer:
        problems.append("issuer missing")
    trusted = {str(x) for x in (expected_issuers or []) if str(x)}
    if trusted and issuer not in trusted:
        problems.append("issuer is not trusted for this evidence type")
    if str(payload.get("status", "")).upper() != "PASS":
        problems.append("attestation status is not PASS")

    subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
    actual_subject = str(subject.get("release_set_digest", "")).strip()
    if not expected_release_set_digest or actual_subject != expected_release_set_digest:
        problems.append("attestation is not bound to this ReleaseSet")

    policy_digest = payload.get("policy_digest")
    if not _digest_ok(policy_digest):
        problems.append("policy_digest missing or invalid")
    if expected_policy_digest and str(policy_digest).lower() != str(expected_policy_digest).lower():
        problems.append("policy_digest mismatch")
    if not _digest_ok(payload.get("evidence_digest")):
        problems.append("evidence_digest missing or invalid")

    nonce = str(payload.get("nonce", "")).strip()
    if not nonce:
        problems.append("nonce missing")
    if expected_nonce is not None and nonce != expected_nonce:
        problems.append("nonce mismatch")

    time_ok, time_detail = temporal_attestation_check(payload, max_age_seconds=max_age_seconds)
    if not time_ok:
        problems.extend(time_detail.get("problems", []))

    sig_ok = False
    sig_detail: dict[str, Any]
    if evidence_type:
        sig_ok, sig_detail = verify_signed_attestation(
            payload, envelope, purpose=attestation_purpose(evidence_type),
            public_keys=public_keys, signature_required=signature_required,
        )
        if not sig_ok:
            problems.append("signature is not trusted/valid")
    else:
        sig_detail = {"status": "UNVERIFIED", "reason": "evidence_type missing"}

    return not problems, {
        "problems": problems,
        "issuer": issuer,
        "evidence_type": evidence_type,
        "freshness": time_detail,
        "signature_verification": sig_detail,
    }
