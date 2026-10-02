from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from diagcore.assurance import parse_time
from diagcore.signing import verify_payload
from .release_set import validate_release_set


def verify_release_authorization(
    verdict: dict[str, Any],
    signature: dict[str, Any],
    *,
    trusted_public_keys: Iterable[Path],
    active_release_set: dict[str, Any],
    allowed_verdicts: Iterable[str] = ("PASS",),
    expected_policy_version: str | None = None,
    now: datetime | None = None,
) -> tuple[bool, dict[str, Any]]:
    """PEP-side fail-closed verifier for the exact release being activated.

    There is intentionally no `run_security_gate`/`skip` parameter. The PEP decides
    whether an operation is gated; a caller cannot ask this verifier to disable itself.
    """
    now = now or datetime.now(timezone.utc)
    problems: list[str] = []

    rs_ok, rs_detail = validate_release_set(active_release_set, require_complete=True)
    if not rs_ok:
        problems.extend(rs_detail.get("problems", []))
    active_digest = str(active_release_set.get("release_set_digest", "")).strip()

    keys = list(trusted_public_keys)
    matched = None
    for key in keys:
        if verify_payload(verdict, signature, key):
            matched = str(key)
            break
    if matched is None:
        problems.append("release authorization signature is not trusted/valid")

    if verdict.get("schema") != "konnaxiondiag.release-verdict.v5":
        problems.append("unsupported release verdict schema")
    authorization = verdict.get("authorization") if isinstance(verdict.get("authorization"), dict) else {}
    if authorization.get("schema") != "konnaxiondiag.release-authorization.v1":
        problems.append("release authorization object missing or invalid")

    top_verdict = str(verdict.get("verdict", "")).upper()
    auth_verdict = str(authorization.get("verdict", "")).upper()
    allowed = {str(x).upper() for x in allowed_verdicts}
    if top_verdict != auth_verdict:
        problems.append("top-level verdict and signed authorization disagree")
    if auth_verdict not in allowed:
        problems.append("release verdict is not activation-acceptable")
    if str(authorization.get("subject", "")).strip() != active_digest:
        problems.append("active ReleaseSet does not match authorization subject")

    issued = parse_time(authorization.get("issued_at"))
    expires = parse_time(authorization.get("expires_at"))
    if issued is None:
        problems.append("authorization issued_at missing or invalid")
    elif issued > now:
        problems.append("authorization issued_at is in the future")
    if expires is None:
        problems.append("authorization expires_at missing or invalid")
    elif expires <= now:
        problems.append("authorization has expired")
    elif issued is not None and expires <= issued:
        problems.append("authorization expires before or at issuance")
    if not str(authorization.get("nonce", "")).strip():
        problems.append("authorization nonce missing")
    if not str(authorization.get("run_id", "")).strip():
        problems.append("authorization run_id missing")
    policy_version = str(authorization.get("policy_version", "")).strip()
    if not policy_version:
        problems.append("authorization policy_version missing")
    if expected_policy_version and policy_version != expected_policy_version:
        problems.append("authorization policy_version mismatch")

    return not problems, {
        "problems": problems,
        "active_release_set_digest": active_digest,
        "authorization_subject": authorization.get("subject"),
        "matched_public_key": matched,
        "release_set_validation": rs_detail,
    }
