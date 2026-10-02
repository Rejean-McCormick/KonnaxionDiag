from __future__ import annotations

import json
import re

from profiles.security.support.remote import run_script, RemoteBlocked

PROCESS_SCRIPT = r"""
set +e
echo "__PROCESSES__"
ps -eo user,pid,ppid,comm,args --no-headers 2>/dev/null
echo "__SYSTEMD_RUNNING__"
systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null
"""

def _section(text: str, name: str, next_name: str | None = None) -> str:
    token = f"__{name}__"
    if token not in text:
        return ""
    chunk = text.split(token, 1)[1]
    if next_name and f"__{next_name}__" in chunk:
        chunk = chunk.split(f"__{next_name}__", 1)[0]
    return chunk.strip()

def _run_process_ioc(cfg, report):
    try:
        r = run_script(cfg, PROCESS_SCRIPT, timeout_seconds=90)
    except RemoteBlocked as exc:
        report.add("runtime.remote.processes", "BLOCKED", "runtime", str(exc))
        return

    if r["exit_code"] != 0:
        report.add(
            "runtime.remote.processes",
            "INFRA_ERROR",
            "runtime",
            "Could not collect runtime process/service evidence.",
            evidence=r,
        )
        return

    text = r["stdout_tail"]
    tokens = [
        str(item).lower()
        for item in cfg.get("remote", {}).get("iocs", {}).get("tokens", [])
    ]
    hits = [
        line[:500]
        for line in text.splitlines()
        if any(token in line.lower() for token in tokens)
    ]
    report.add(
        "runtime.incident_ioc",
        "FAIL" if hits else "PASS",
        "incident_recovery",
        "Known incident IOC matched running process/service state."
        if hits
        else "No configured incident IOC matched running process/service state.",
        evidence=hits[:100] if hits else None,
    )

    suspicious = [
        line[:500]
        for line in text.splitlines()
        if re.search(r"/(tmp|dev/shm)/", line)
        and re.search(r"\b(python|bash|sh|curl|wget|sshd|xmrig)\b", line, re.I)
    ]
    report.add(
        "runtime.temp_exec.processes",
        "WARN" if suspicious else "PASS",
        "runtime",
        "Processes executing from temporary/shared-memory paths require review."
        if suspicious
        else "No obvious process executing from /tmp or /dev/shm was detected.",
        evidence=suspicious[:100] if suspicious else None,
    )

def _parse_env_lines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result

def _run_capsule_manager(cfg, report):
    from profiles.security.support.capsule_manager import (
        capsule_enabled,
        gate_is_release_acceptable,
        release_required_gate_checks,
        remote_probe_script,
    )

    if not capsule_enabled(cfg):
        report.add(
            "capsule.agent.integration",
            "SKIP",
            "capsule_security",
            "Capsule Manager integration is disabled.",
        )
        return

    try:
        script = remote_probe_script(cfg)
    except ValueError as exc:
        verdict = (
            "BLOCKED"
            if cfg.get("capsule_manager", {}).get("require_for_release", True)
            else "WARN"
        )
        report.add(
            "capsule.agent.integration",
            verdict,
            "capsule_security",
            str(exc),
        )
        return

    try:
        result = run_script(cfg, script, privileged=True, timeout_seconds=120)
    except RemoteBlocked as exc:
        report.add(
            "capsule.agent.integration",
            "BLOCKED",
            "capsule_security",
            str(exc),
            recommendation=(
                "Enable read-only noninteractive sudo evidence only for an audited ops account."
            ),
        )
        return

    if result["exit_code"] != 0:
        report.add(
            "capsule.agent.integration",
            "INFRA_ERROR",
            "capsule_security",
            "Could not collect Capsule Manager Agent evidence.",
            evidence=result,
        )
        return

    text = result["stdout_tail"]

    listener = _section(text, "KX_AGENT_LISTENER", "KX_AGENT_SERVICE")
    cm = cfg.get("capsule_manager", {})
    port = int(cm.get("agent_port", 8765))
    public_listener = [
        line for line in listener.splitlines()
        if re.search(rf"(?:0\.0\.0\.0|\[::\]|:::|\*):{port}\b", line)
    ]
    require_release = bool(cm.get("require_for_release", True))
    require_local = True if require_release else bool(cm.get("require_local_agent_bind", True))

    if public_listener:
        listener_verdict = "FAIL"
        listener_message = "Konnaxion Agent is listening on a public/wildcard interface."
    elif listener:
        loopback_only = all(
            ("127.0.0.1:" in line or "[::1]:" in line or "::1:" in line)
            for line in listener.splitlines()
            if line.strip()
        )
        listener_verdict = "PASS" if loopback_only else ("FAIL" if require_local else "WARN")
        listener_message = (
            "Konnaxion Agent listener is local-only."
            if loopback_only
            else "Konnaxion Agent listener could not be proven loopback-only."
        )
    else:
        listener_verdict = "FAIL" if require_local else "WARN"
        listener_message = "Konnaxion Agent listener was not detected."

    report.add(
        "capsule.agent.local_bind",
        listener_verdict,
        "capsule_security",
        listener_message,
        evidence=listener or None,
        release_blocker=listener_verdict == "FAIL",
    )

    service = _section(text, "KX_AGENT_SERVICE", "KX_TOKEN_STAT")
    service_props = _parse_env_lines(service)
    expected_user = str(cm.get("expected_agent_user", "kx-agent"))
    actual_user = service_props.get("User", "")
    report.add(
        "capsule.agent.service_user",
        "PASS" if actual_user == expected_user else "FAIL",
        "capsule_security",
        f"Agent service runs as {actual_user or 'unknown'}; expected {expected_user}.",
        evidence=service_props,
        release_blocker=actual_user != expected_user,
    )

    hardening_keys = {
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
    }
    weak = {
        key: service_props.get(key)
        for key, expected in hardening_keys.items()
        if service_props.get(key, "").lower() != expected
    }
    report.add(
        "capsule.agent.systemd_hardening",
        "WARN" if weak else "PASS",
        "capsule_security",
        "Agent systemd hardening can be strengthened."
        if weak
        else "Agent service declares baseline systemd hardening.",
        evidence={"weak": weak, "properties": service_props},
    )

    token_stat = _section(text, "KX_TOKEN_STAT", "KX_AUDIT_STAT")
    token_mode = token_stat.split("|", 1)[0] if token_stat else ""
    token_ok = token_mode in {"600", "400", "640"}
    report.add(
        "capsule.agent.token_permissions",
        "PASS" if token_ok else "FAIL",
        "capsule_security",
        "Agent token file permissions are restricted."
        if token_ok
        else "Agent token file is missing or permissions are not restricted.",
        evidence=token_stat or None,
        release_blocker=not token_ok,
    )

    audit_stat = _section(text, "KX_AUDIT_STAT", "KX_RUNTIME_PROFILE")
    audit_mode = audit_stat.split("|", 1)[0] if audit_stat else ""
    audit_ok = audit_mode in {"600", "640", "400", "440"}
    report.add(
        "capsule.agent.audit_log",
        "PASS" if audit_ok else "FAIL",
        "capsule_security",
        "Agent append-only audit evidence file exists with restricted permissions."
        if audit_ok
        else "Agent audit evidence is missing or broadly permissioned.",
        evidence=audit_stat or None,
        release_blocker=not audit_ok,
    )

    profile_text = _section(text, "KX_RUNTIME_PROFILE", "KX_SECURITY_GATE")
    profile = _parse_env_lines(profile_text)
    network_profile = profile.get("KX_NETWORK_PROFILE", "")
    exposure = profile.get("KX_EXPOSURE_MODE", "")
    expires = profile.get("KX_PUBLIC_MODE_EXPIRES_AT", "")
    profile_problem = None
    if network_profile == "public_temporary" and not expires:
        profile_problem = "public_temporary requires KX_PUBLIC_MODE_EXPIRES_AT."
    report.add(
        "capsule.network_profile",
        "FAIL" if profile_problem else ("PASS" if network_profile else "WARN"),
        "capsule_security",
        profile_problem
        or (
            f"Runtime profile is {network_profile} / {exposure or 'unspecified'}."
            if network_profile
            else "Runtime network profile evidence was not found."
        ),
        evidence=profile or None,
        release_blocker=bool(profile_problem),
    )

    gate_text = _section(text, "KX_SECURITY_GATE")
    try:
        payload = json.loads(gate_text) if gate_text else {"status": "UNKNOWN"}
    except json.JSONDecodeError:
        payload = {"status": "UNKNOWN", "reason": "invalid security-gate.json"}

    try:
        required_checks = release_required_gate_checks(cfg)
    except ValueError as exc:
        report.add(
            "capsule.security_gate.evidence",
            "CONFIG_ERROR",
            "capsule_security",
            str(exc),
            release_blocker=True,
        )
        return

    acceptable, detail = gate_is_release_acceptable(
        payload,
        unknown_is_blocking=(True if require_release else bool(cm.get("unknown_is_blocking", True))),
        required_checks=required_checks,
    )
    status = detail["status"]
    gate_verdict = "PASS" if acceptable else "FAIL"
    report.add(
        "capsule.security_gate.evidence",
        gate_verdict,
        "capsule_security",
        f"Capsule Manager Security Gate status: {status}.",
        evidence=detail,
        recommendation=(
            "Run the complete Capsule Manager Security Gate and resolve missing, SKIPPED, FAIL_BLOCKING, or UNKNOWN required checks."
            if not acceptable
            else None
        ),
        release_blocker=not acceptable,
    )

def run(cfg, report):
    _run_process_ioc(cfg, report)
    _run_capsule_manager(cfg, report)
