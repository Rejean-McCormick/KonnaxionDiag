from __future__ import annotations

import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SAFE_INSTANCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SAFE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")

CANONICAL_CAPSULE_STATUSES = {
    "PASS", "WARN", "FAIL_BLOCKING", "SKIPPED", "UNKNOWN"
}

# SecurityDiag release qualification is intentionally stricter than the
# Capsule Manager startup gate: every check declared required by the canonical
# policy must be present. WARN remains usable evidence, but SKIPPED does not.
DEFAULT_REQUIRED_GATE_CHECKS = (
    "capsule_signature",
    "image_checksums",
    "manifest_schema",
    "secrets_present",
    "secrets_not_default",
    "firewall_enabled",
    "dangerous_ports_blocked",
    "postgres_not_public",
    "redis_not_public",
    "docker_socket_not_mounted",
    "no_privileged_containers",
    "no_host_network",
    "allowed_images_only",
    "admin_surface_private",
    "backup_configured",
)


def resolve_capsule_repo(cfg: dict[str, Any]) -> Path | None:
    cm = cfg.get("capsule_manager", {})
    raw = str(cm.get("repo_root", "auto")).strip()
    target = Path(cfg["_target_root"]).resolve(strict=False)
    if raw.lower() == "auto":
        candidate = target.parent / "Konnaxion_Capsule_Manager"
    else:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = target / candidate
    candidate = candidate.resolve(strict=False)
    return candidate if candidate.exists() and candidate.is_dir() else None


def capsule_enabled(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("capsule_manager", {}).get("enabled", False))


def instance_id(cfg: dict[str, Any]) -> str:
    value = str(cfg.get("capsule_manager", {}).get("instance_id", "")).strip()
    if not value:
        return ""
    if not SAFE_INSTANCE_ID.fullmatch(value):
        raise ValueError("capsule_manager.instance_id contains unsafe characters")
    return value


def _safe_service_name(value: Any) -> str:
    service = str(value).strip()
    if not service or not SAFE_SERVICE_NAME.fullmatch(service):
        raise ValueError("capsule_manager.agent_service_name contains unsafe characters")
    return service


def _safe_remote_path(value: Any, field: str) -> str:
    text = str(value).strip()
    if not text or any(ch in text for ch in ("\x00", "\r", "\n")):
        raise ValueError(f"{field} is missing or contains unsafe control characters")
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be an absolute normalized POSIX path")
    return str(path)


def _safe_remote_template(value: Any, field: str, iid: str) -> str:
    template = str(value).strip()
    if template.count("{instance_id}") > 1:
        raise ValueError(f"{field} contains multiple instance_id placeholders")
    try:
        rendered = template.format(instance_id=iid)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{field} contains an unsupported format placeholder") from exc
    return _safe_remote_path(rendered, field)


def inspect_local_policy(repo: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    cm = cfg.get("capsule_manager", {})
    files = cm.get("policy_files", {})
    result: dict[str, Any] = {"repo": str(repo), "files": {}, "checks": {}}

    for key, rel in files.items():
        path = (repo / str(rel)).resolve(strict=False)
        try:
            path.relative_to(repo)
        except ValueError:
            result["files"][key] = {"exists": False, "unsafe_path": True}
            continue
        result["files"][key] = {"exists": path.exists(), "path": str(path)}

    auth = repo / str(files.get("agent_auth", "kx_agent/auth.py"))
    runtime = repo / str(files.get("runtime", "policies/runtime_policy.yaml"))
    gate = repo / str(files.get("security_gate", "policies/security_gate.yaml"))

    auth_text = auth.read_text(encoding="utf-8", errors="replace") if auth.exists() else ""
    runtime_text = runtime.read_text(encoding="utf-8", errors="replace") if runtime.exists() else ""
    gate_text = gate.read_text(encoding="utf-8", errors="replace") if gate.exists() else ""

    checks = result["checks"]
    checks["agent_local_bind_declared"] = all(x in auth_text for x in ("127.0.0.1", "::1", "LOCAL_BIND_HOSTS"))
    checks["agent_forbidden_operations_declared"] = "FORBIDDEN_AGENT_OPERATIONS" in auth_text and "shell.exec" in auth_text and "docker.run" in auth_text
    checks["runtime_private_by_default"] = "deny_by_default: true" in runtime_text
    checks["runtime_blocks_privileged"] = "privileged_allowed: false" in runtime_text
    checks["runtime_blocks_host_network"] = "host_network_allowed: false" in runtime_text
    checks["runtime_blocks_docker_socket"] = "docker_socket_mount_allowed: false" in runtime_text
    checks["runtime_blocks_unknown_images"] = "unknown_images_allowed: false" in runtime_text
    checks["runtime_requires_signed_capsules"] = "reject_unsigned_capsules: true" in runtime_text
    checks["gate_has_fail_blocking"] = "FAIL_BLOCKING" in gate_text
    checks["gate_has_unknown"] = "UNKNOWN" in gate_text
    checks["temporary_public_requires_expiration"] = "requires_expiration: true" in gate_text or "public_temporary_requires_expiration: true" in runtime_text
    return result


def gate_status_from_payload(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    status = str(
        payload.get("security_status")
        or payload.get("status")
        or summary.get("status")
        or "UNKNOWN"
    ).strip().upper()
    return status if status in CANONICAL_CAPSULE_STATUSES else "UNKNOWN"


def normalize_gate_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("checks")
    if raw is None:
        raw = payload.get("results")
    if raw is None and isinstance(payload.get("report"), dict):
        raw = payload["report"].get("results")

    out: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        for check, value in raw.items():
            if isinstance(value, dict):
                status = str(value.get("status", "UNKNOWN")).strip().upper()
                message = str(value.get("message", ""))
                blocking = bool(value.get("blocking", False))
            else:
                status = str(value).strip().upper()
                message = ""
                blocking = False
            if status not in CANONICAL_CAPSULE_STATUSES:
                status = "UNKNOWN"
            out.append({
                "check": str(check).strip(),
                "status": status,
                "message": message,
                "blocking": blocking,
            })
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                status = str(item.get("status") or "UNKNOWN").strip().upper()
                if status not in CANONICAL_CAPSULE_STATUSES:
                    status = "UNKNOWN"
                out.append({
                    "check": str(item.get("check") or item.get("id") or item.get("name") or "").strip(),
                    "status": status,
                    "message": str(item.get("message") or ""),
                    "blocking": bool(item.get("blocking", False)),
                })
    return out


def _normalize_required_checks(required_checks: Iterable[str] | None) -> tuple[str, ...]:
    raw = DEFAULT_REQUIRED_GATE_CHECKS if required_checks is None else required_checks
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        check = str(item).strip()
        if check and check not in seen:
            seen.add(check)
            out.append(check)
    return tuple(out)


def release_required_gate_checks(cfg: dict[str, Any]) -> tuple[str, ...]:
    """Validate configured release checks without allowing the baseline to weaken."""
    configured = cfg.get("capsule_manager", {}).get("required_gate_checks")
    if configured is None:
        return DEFAULT_REQUIRED_GATE_CHECKS
    if not isinstance(configured, (list, tuple)):
        raise ValueError("capsule_manager.required_gate_checks must be a list of check ids")
    normalized = _normalize_required_checks(configured)
    missing_baseline = [check for check in DEFAULT_REQUIRED_GATE_CHECKS if check not in normalized]
    if missing_baseline:
        raise ValueError(
            "capsule_manager.required_gate_checks omits canonical required checks: "
            + ", ".join(missing_baseline)
        )
    return normalized


def gate_is_release_acceptable(
    payload: dict[str, Any],
    *,
    unknown_is_blocking: bool = True,
    required_checks: Iterable[str] | None = None,
) -> tuple[bool, dict[str, Any]]:
    status = gate_status_from_payload(payload)
    results = normalize_gate_results(payload)
    required = _normalize_required_checks(required_checks)

    by_check = {item["check"]: item for item in results if item.get("check")}
    missing = [check for check in required if check not in by_check]
    skipped_required = [
        by_check[check]
        for check in required
        if check in by_check and by_check[check]["status"] == "SKIPPED"
    ]
    blocking = [
        item for item in results
        if item["status"] == "FAIL_BLOCKING"
        or (unknown_is_blocking and item["status"] == "UNKNOWN")
    ]

    # A release PASS/WARN is meaningful only when the complete required evidence
    # set is present. This intentionally rejects forged/partial aggregate PASS.
    acceptable = (
        status in {"PASS", "WARN"}
        and bool(results)
        and not missing
        and not skipped_required
        and not blocking
    )
    return acceptable, {
        "status": status,
        "blocking": blocking,
        "missing_required_checks": missing,
        "skipped_required_checks": skipped_required,
        "required_checks": list(required),
        "results": results,
    }


def remote_probe_script(cfg: dict[str, Any]) -> str:
    cm = cfg.get("capsule_manager", {})
    iid = instance_id(cfg)
    if not iid:
        raise ValueError("capsule_manager.instance_id is required for remote Capsule Manager checks")

    gate_path = _safe_remote_template(
        cm.get("security_gate_remote_path_template", "/opt/konnaxion/instances/{instance_id}/state/security-gate.json"),
        "capsule_manager.security_gate_remote_path_template",
        iid,
    )
    env_path = _safe_remote_template(
        cm.get("runtime_env_remote_path_template", "/opt/konnaxion/instances/{instance_id}/env/runtime.env"),
        "capsule_manager.runtime_env_remote_path_template",
        iid,
    )
    token_path = _safe_remote_path(
        cm.get("agent_token_path", "/opt/konnaxion/manager/agent.token"),
        "capsule_manager.agent_token_path",
    )
    audit_path = _safe_remote_path(
        cm.get("audit_path", "/opt/konnaxion/agent/audit/agent-audit.jsonl"),
        "capsule_manager.audit_path",
    )
    service = _safe_service_name(cm.get("agent_service_name", "kx-agent"))
    try:
        port = int(cm.get("agent_port", 8765))
    except (TypeError, ValueError) as exc:
        raise ValueError("capsule_manager.agent_port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("capsule_manager.agent_port must be between 1 and 65535")

    q_gate = shlex.quote(gate_path)
    q_env = shlex.quote(env_path)
    q_token = shlex.quote(token_path)
    q_audit = shlex.quote(audit_path)
    q_service = shlex.quote(service)

    # The fixed probe is read-only. All configurable shell words are either
    # validated identifiers/integers or shell-quoted absolute paths.
    return f"""
set +e
echo "__KX_AGENT_LISTENER__"
ss -ltnp 2>/dev/null | grep -E ':{port}[[:space:]]' || true
echo "__KX_AGENT_SERVICE__"
systemctl show {q_service} -p User -p Group -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp -p RestrictSUIDSGID -p CapabilityBoundingSet -p AmbientCapabilities 2>/dev/null || true
echo "__KX_TOKEN_STAT__"
stat -Lc '%a|%U|%G|%n' -- {q_token} 2>/dev/null || true
echo "__KX_AUDIT_STAT__"
stat -Lc '%a|%U|%G|%s|%Y|%n' -- {q_audit} 2>/dev/null || true
echo "__KX_RUNTIME_PROFILE__"
if [ -r {q_env} ]; then
  grep -E '^(KX_NETWORK_PROFILE|KX_EXPOSURE_MODE|KX_PUBLIC_MODE_ENABLED|KX_PUBLIC_MODE_EXPIRES_AT|KX_HOST)=' -- {q_env} 2>/dev/null || true
fi
echo "__KX_SECURITY_GATE__"
if [ -r {q_gate} ]; then
  cat -- {q_gate}
else
  echo '{{"status":"UNKNOWN","reason":"security-gate evidence file missing"}}'
fi
"""
