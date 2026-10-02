from __future__ import annotations

from pathlib import Path

from diagcore.manifest import load_manifest
from diagcore.utils import read_json
from diagcore.release_gate import disposition_valid

RELEASE_ACCEPTABLE = {"PASS"}
VALID_RELEASE_PROFILES = {"standard_release", "incident_recovery"}


def _warn_dispositions(cfg) -> dict:
    gate = cfg.get("release_gate", {}) if isinstance(cfg.get("release_gate", {}), dict) else {}
    release = cfg.get("release", {}) if isinstance(cfg.get("release", {}), dict) else {}
    value = gate.get("security_warn_dispositions", release.get("warn_dispositions", {}))
    return value if isinstance(value, dict) else {}

def _unresolved_warns(result: dict, cfg) -> list[str]:
    if result.get("verdict") != "WARN":
        return []
    dispositions = _warn_dispositions(cfg)
    ids = [str(f.get("id", "")) for f in result.get("findings", []) if f.get("verdict") == "WARN"]
    return [fid for fid in ids if not disposition_valid(dispositions.get(fid))]

def _release_acceptable_result(result: dict, cfg) -> bool:
    verdict = result.get("verdict")
    if verdict == "PASS":
        return True
    if verdict == "WARN":
        return not _unresolved_warns(result, cfg)
    return False


def _release_profile(cfg) -> str:
    release_cfg = cfg.get("release", {})
    profile = str(release_cfg.get("profile", "standard_release")).strip().lower()
    if profile not in VALID_RELEASE_PROFILES:
        allowed = ", ".join(sorted(VALID_RELEASE_PROFILES))
        raise ValueError(f"release.profile must be one of: {allowed}")
    return profile


def _attestation_state(release_cfg: dict, profile: str) -> tuple[bool, list[str], list[str]]:
    attestations = release_cfg.get("attestations", {})
    missing = [key for key, value in attestations.items() if value is not True]
    recorded = [key for key, value in attestations.items() if value is True]
    required = profile == "incident_recovery" and bool(
        release_cfg.get("require_attestations", True)
    )
    return required, missing, recorded


def _load_prior(run_root: Path) -> list[dict]:
    level_root = run_root / "levels"
    prior = []
    if not level_root.exists():
        return prior

    for path in sorted(level_root.glob("S*/result.json")):
        try:
            result = read_json(path)
        except Exception:
            continue
        if result.get("level_id") == "S14":
            continue
        prior.append(result)
    return prior


def _capsule_gate_evidence(prior: list[dict]) -> dict | None:
    for result in prior:
        if result.get("level_id") != "S09":
            continue
        for finding in result.get("findings", []):
            if finding.get("id") == "capsule.security_gate.evidence":
                return finding
    return None


def _required_prior_level_ids(cfg) -> list[str]:
    tool_root = Path(cfg.get("_tool_root", ""))
    manifest = load_manifest(tool_root)
    release_ids = (
        manifest.get("campaigns", {})
        .get("release", {})
        .get("levels", [])
    )
    meta_by_id = {
        item.get("id"): item
        for item in manifest.get("levels", [])
        if item.get("id")
    }
    return [
        level_id
        for level_id in release_ids
        if level_id != "S14" and bool(meta_by_id.get(level_id, {}).get("required", False))
    ]


def run(cfg, report):
    run_root = Path(cfg.get("_run_root", ""))
    prior_results = _load_prior(run_root)

    prior = [
        {
            "id": item.get("level_id"),
            "name": item.get("level_name"),
            "verdict": item.get("verdict"),
        }
        for item in prior_results
    ]
    prior_by_id = {item["id"]: item for item in prior if item.get("id")}

    manifest_error = None
    try:
        expected = _required_prior_level_ids(cfg)
    except Exception as exc:  # fail closed: release completeness cannot be proven
        expected = []
        manifest_error = f"{type(exc).__name__}: {exc}"

    missing_levels = [level_id for level_id in expected if level_id not in prior_by_id]
    expected_set = set(expected)
    results_by_id = {item.get("level_id"): item for item in prior_results}
    bad = [
        item for item in prior
        if item.get("id") in expected_set
        and not _release_acceptable_result(results_by_id.get(item.get("id"), {}), cfg)
    ]
    warns = [item for item in prior if item.get("verdict") == "WARN"]
    unresolved_warns = {
        level_id: _unresolved_warns(results_by_id.get(level_id, {}), cfg)
        for level_id in expected
        if _unresolved_warns(results_by_id.get(level_id, {}), cfg)
    }
    technical_complete = not manifest_error and not missing_levels and not bad and not unresolved_warns

    report.add(
        "release.prior_levels.complete",
        "CONFIG_ERROR" if manifest_error else ("FAIL" if not technical_complete else "PASS"),
        "release_gate",
        "Release-level completeness could not be resolved from the SecurityDiag manifest."
        if manifest_error
        else (
            "One or more required security levels are missing or not release-acceptable."
            if not technical_complete
            else "All required prior release levels are present and release-acceptable."
        ),
        evidence={
            "expected": expected,
            "missing": missing_levels,
            "bad": bad,
            "warnings": warns,
            "unresolved_warning_dispositions": unresolved_warns,
            "manifest_error": manifest_error,
        },
        release_blocker=not technical_complete,
    )

    report.add(
        "release.warning_dispositions",
        "FAIL" if unresolved_warns else "PASS",
        "release_gate",
        "Security WARN findings require an explicit accepted disposition before release." if unresolved_warns else
        "All security WARN findings are absent or explicitly dispositioned.",
        evidence=unresolved_warns or None,
        release_blocker=bool(unresolved_warns),
    )

    cm = cfg.get("capsule_manager", {})
    cm_required = bool(cm.get("require_for_release", True))
    cm_enabled = bool(cm.get("enabled", False))
    if cm_required:
        if not cm_enabled:
            report.add(
                "release.capsule_manager.security_gate",
                "FAIL",
                "release_gate",
                "Capsule Manager release integration is required but disabled.",
                recommendation="Enable and configure capsule_manager before the release campaign.",
                release_blocker=True,
            )
            capsule_ok = False
        else:
            gate = _capsule_gate_evidence(prior_results)
            if gate is None:
                report.add(
                    "release.capsule_manager.security_gate",
                    "FAIL",
                    "release_gate",
                    "Capsule Manager Security Gate evidence is missing from S09.",
                    recommendation=(
                        "Configure capsule_manager.instance_id and run S09/host evidence "
                        "before release."
                    ),
                    release_blocker=True,
                )
                capsule_ok = False
            else:
                capsule_ok = gate.get("verdict") == "PASS"
                report.add(
                    "release.capsule_manager.security_gate",
                    "PASS" if capsule_ok else "FAIL",
                    "release_gate",
                    "Capsule Manager Security Gate evidence is release-acceptable."
                    if capsule_ok
                    else "Capsule Manager Security Gate is not release-acceptable.",
                    evidence=gate.get("evidence"),
                    release_blocker=not capsule_ok,
                )
    else:
        capsule_ok = True
        report.add(
            "release.capsule_manager.security_gate",
            "SKIP",
            "release_gate",
            "Capsule Manager release integration is explicitly not required.",
        )

    release_cfg = cfg.get("release", {})
    profile_error = None
    try:
        release_profile = _release_profile(cfg)
    except Exception as exc:
        release_profile = "invalid"
        profile_error = f"{type(exc).__name__}: {exc}"

    report.add(
        "release.profile",
        "CONFIG_ERROR" if profile_error else "PASS",
        "release_gate",
        "Release profile is invalid."
        if profile_error
        else f"Release profile: {release_profile}.",
        evidence={
            "profile": release_profile,
            "allowed": sorted(VALID_RELEASE_PROFILES),
            "error": profile_error,
        },
        release_blocker=bool(profile_error),
    )

    if profile_error:
        attestations_required = False
        missing_attestations = []
        recorded_attestations = []
    else:
        attestations_required, missing_attestations, recorded_attestations = _attestation_state(
            release_cfg, release_profile
        )

    blocking_attestations = missing_attestations if attestations_required else []

    if release_profile == "incident_recovery" and attestations_required:
        report.add(
            "release.incident_recovery.attestations",
            "BLOCKED" if blocking_attestations else "PASS",
            "release_gate",
            "Required incident-recovery attestations are incomplete."
            if blocking_attestations
            else "All required incident-recovery attestations are recorded.",
            evidence={
                "profile": release_profile,
                "missing": blocking_attestations,
                "recorded": recorded_attestations,
            },
            recommendation=(
                "Verify each human-controlled recovery condition before declaring an "
                "incident-recovery release."
                if blocking_attestations
                else None
            ),
        )
    elif release_profile == "incident_recovery":
        blocking_attestations = missing_attestations or ["attestation-policy-disabled"]
        report.add(
            "release.incident_recovery.attestations",
            "BLOCKED",
            "release_gate",
            "Incident-recovery attestations cannot be disabled for a release decision.",
            evidence={
                "profile": release_profile,
                "unrecorded": missing_attestations,
                "recorded": recorded_attestations,
            },
        )
    elif not profile_error:
        report.add(
            "release.incident_recovery.attestations",
            "SKIP",
            "release_gate",
            "Incident-recovery attestations are not required for the standard release profile.",
            evidence={
                "profile": release_profile,
                "unrecorded": missing_attestations,
                "recorded": recorded_attestations,
            },
        )

    gate_technical_ok = technical_complete and capsule_ok and not profile_error

    if gate_technical_ok and not blocking_attestations:
        report.add(
            "release.security_gate",
            "PASS",
            "release_gate",
            "SecurityDiag + Capsule Manager release gate is satisfied with no unresolved required-level warnings.",
        )
    elif not gate_technical_ok:
        report.add(
            "release.security_gate",
            "FAIL",
            "release_gate",
            "Combined release gate is not satisfied due to missing/failed/incomplete technical evidence or invalid release profile.",
            release_blocker=True,
        )
    else:
        report.add(
            "release.security_gate",
            "BLOCKED",
            "release_gate",
            "Incident-recovery release gate awaits required human attestations.",
            release_blocker=True,
        )
