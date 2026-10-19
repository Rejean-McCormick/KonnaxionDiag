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


def verify_activation_admission(
    verdict: dict[str, Any],
    signature: dict[str, Any],
    *,
    trusted_public_keys: Iterable[Path],
    active_release_set: dict[str, Any],
    measured_release_set_digest: str,
    expected_policy_version: str,
    now: datetime | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Strict activation PEP entry point. The Agent MUST measure `measured_*` itself.

    `active_release_set` and this measurement must come from an Agent-controlled,
    independently trusted deployment state, never a caller-supplied claim.
    This function does not read runtime images or compute that independent state.
    """
    problems: list[str] = []
    expected_policy = str(expected_policy_version or "").strip()
    measured = str(measured_release_set_digest or "").strip()
    if not expected_policy:
        problems.append("Agent expected policy version is required")
    if not (measured.startswith("sha256:") and len(measured) == 71 and
            all(ch in "0123456789abcdef" for ch in measured[7:])):
        problems.append("Agent-measured ReleaseSet digest is missing or invalid")

    # Materialize key sequence only once, to avoid generator exhaustion.
    keys = tuple(trusted_public_keys)
    if not keys:
        problems.append("no trusted release authority public keys configured")
    if not isinstance(signature, dict):
        problems.append("detached release signature is missing")
    else:
        from diagcore.signing import SIGNATURE_SCHEMA, SIGNATURE_PURPOSE
        if signature.get("schema") != SIGNATURE_SCHEMA:
            problems.append("unsupported release signature envelope")
        if signature.get("purpose") != SIGNATURE_PURPOSE:
            problems.append("release signature purpose mismatch")
        if signature.get("algorithm") != "ed25519":
            problems.append("release signature algorithm mismatch")
        fingerprint = str(signature.get("public_key_fingerprint_sha256", ""))
        if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
            problems.append("release signing key fingerprint is missing or invalid")

    if not isinstance(verdict, dict) or not isinstance(active_release_set, dict):
        problems.append("release verdict or active ReleaseSet is malformed")
        return False, {"problems": problems, "measured_release_set_digest": measured}

    ok, detail = verify_release_authorization(
        verdict, signature if isinstance(signature, dict) else {},
        trusted_public_keys=keys, active_release_set=active_release_set,
        allowed_verdicts=("PASS",), expected_policy_version=expected_policy,
        now=now,
    )
    problems.extend(detail.get("problems", []))
    # Signature metadata is outside the signed verdict; never accept a forged
    # key fingerprint that differs from the key that actually verified Ed25519.
    if detail.get("matched_public_key") is not None and isinstance(signature, dict):
        from diagcore.signing import _load_public_key, _public_fingerprint
        verified_key = _load_public_key(Path(detail["matched_public_key"]))
        if verified_key is None or signature.get("public_key_fingerprint_sha256") != _public_fingerprint(verified_key):
            problems.append("release signing key fingerprint does not match verifying authority")
    active_digest = str(active_release_set.get("release_set_digest", ""))
    if measured != active_digest:
        problems.append("Agent-measured ReleaseSet digest does not match supplied ReleaseSet")

    signed_release_set = verdict.get("release_set")
    if not isinstance(signed_release_set, dict):
        problems.append("signed release verdict contains no ReleaseSet")
    elif signed_release_set != active_release_set:
        problems.append("signed ReleaseSet differs from Agent active ReleaseSet")

    subject_binding = verdict.get("subject_binding")
    if not isinstance(subject_binding, dict) or subject_binding.get("required") is not True or subject_binding.get("valid") is not True:
        problems.append("release subject binding is not mandatory and valid")
    elif subject_binding.get("release_set_digest") != active_digest:
        problems.append("release subject binding digest mismatch")

    for name in ("qualification_policy_digest", "security_contract_registry_digest", "security_evidence_set_digest"):
        value = str(active_release_set.get(name) or "")
        if not (value.startswith("sha256:") and len(value) == 71 and
                all(ch in "0123456789abcdef" for ch in value[7:])):
            problems.append(f"active ReleaseSet {name} is not a valid digest")
    if active_release_set.get("complete") is not True or active_release_set.get("problems") != []:
        problems.append("active ReleaseSet is incomplete or contains unresolved problems")
    # The 1.0 production admission profile requires the complete senior ReleaseSet,
    # rather than trusting a self-declared `complete: true` from a weaker campaign.
    components = {"source", "capsule", "images", "runtime_pack", "policy_bundle", "infra_manifest", "sbom", "provenance"}
    declared = active_release_set.get("required_components")
    if not isinstance(declared, list) or not components.issubset(set(str(x) for x in declared)):
        problems.append("production ReleaseSet required component policy is incomplete")
    identity = active_release_set.get("identity") if isinstance(active_release_set.get("identity"), dict) else {}
    present = {
        "source": bool(identity.get("source_commit_sha") and identity.get("source_tree_digest")),
        "capsule": bool(identity.get("capsule_digest") or identity.get("capsule_digests")),
        "images": bool(identity.get("image_digests")),
        "runtime_pack": bool(identity.get("runtime_pack_digest")),
        "policy_bundle": bool(identity.get("policy_bundle_digest")),
        "infra_manifest": bool(identity.get("infra_manifest_digest")),
        "sbom": bool(identity.get("sbom_digest")),
        "provenance": bool(identity.get("provenance_digest")),
    }
    for component, exists in present.items():
        if not exists:
            problems.append(f"production ReleaseSet component missing: {component}")
    if not isinstance(verdict.get("security"), dict) or (
        verdict["security"].get("clean") is not True or
        verdict["security"].get("s14_verdict") != "PASS"
    ):
        problems.append("signed security qualification is not clean and PASS")
    if not isinstance(verdict.get("functional"), dict) or verdict["functional"].get("clean") is not True:
        problems.append("signed functional qualification is not clean")
    if not isinstance(verdict.get("target_protection"), dict) or verdict["target_protection"].get("verdict") != "PASS":
        problems.append("target protection does not pass")
    if not isinstance(verdict.get("signature"), dict) or verdict["signature"].get("status") != "SIGNED":
        problems.append("signed verdict does not declare a signed release")
    authorization = verdict.get("authorization") if isinstance(verdict.get("authorization"), dict) else {}
    contract = verdict.get("consumer_contract") if isinstance(verdict.get("consumer_contract"), dict) else {}
    if verdict.get("run_id") != authorization.get("run_id"):
        problems.append("signed verdict run ID differs from release authorization")
    if authorization.get("subject") != active_digest:
        problems.append("signed authorization subject differs from active ReleaseSet")
    if contract.get("caller_may_disable_gate") is not False:
        problems.append("signed consumer contract does not prohibit caller bypass")

    detail["problems"] = list(dict.fromkeys(problems))
    detail["measured_release_set_digest"] = measured
    detail["policy_version_enforced"] = expected_policy
    return bool(ok and not problems), detail
