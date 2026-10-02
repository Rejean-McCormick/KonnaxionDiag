from __future__ import annotations
import re, shutil
from pathlib import Path
from profiles.security.support.scanner import iter_files, bounded_text
from diagcore.commands import normalize_command, run_command

SHA40=re.compile(r"^[0-9a-fA-F]{40}$")


def _validate_declared_audit_command(command):
    """Return normalized argv for approved read-only vulnerability audits."""
    argv = normalize_command(command)
    if not argv:
        raise ValueError("Audit command is empty.")
    exe = Path(argv[0]).name.lower()
    if exe.endswith(".exe"):
        exe = exe[:-4]

    lower = [str(x).lower() for x in argv]
    forbidden = {"fix", "--fix", "--force", "--output", "-o"}
    if any(
        token in forbidden
        or token.startswith("--output=")
        or token.startswith("--fix=")
        or (token.startswith("-o") and token != "-o")
        for token in lower[1:]
    ):
        raise ValueError("Audit command contains a mutating/output option not allowed by SecurityDiag.")

    approved = False
    if exe in {"pnpm", "npm", "yarn"}:
        approved = len(lower) >= 2 and lower[1] == "audit"
    elif exe == "pip-audit":
        approved = True
    elif exe in {"python", "python3", "py"}:
        approved = len(lower) >= 3 and lower[1:3] == ["-m", "pip_audit"]

    if not approved:
        raise ValueError(
            "Declared audits are limited to package-manager vulnerability audit commands "
            "(pnpm/npm/yarn audit or pip-audit)."
        )
    return argv


def _run_capsule_manager_alignment(cfg, report):
    from profiles.security.support.capsule_manager import (
        capsule_enabled,
        inspect_local_policy,
        resolve_capsule_repo,
    )

    if not capsule_enabled(cfg):
        report.add(
            "capsule_manager.local_policy",
            "SKIP",
            "capsule_security",
            "Capsule Manager integration is disabled.",
        )
        return

    repo = resolve_capsule_repo(cfg)
    if repo is None:
        verdict = (
            "BLOCKED"
            if cfg.get("capsule_manager", {}).get("require_for_release", True)
            else "WARN"
        )
        report.add(
            "capsule_manager.local_policy",
            verdict,
            "capsule_security",
            "Capsule Manager repository could not be resolved.",
            recommendation=(
                "Set capsule_manager.repo_root or place "
                "Konnaxion_Capsule_Manager beside the Konnaxion repository."
            ),
        )
        return

    evidence = inspect_local_policy(repo, cfg)
    checks = evidence.get("checks", {})
    failed = sorted(name for name, ok in checks.items() if ok is not True)

    report.add(
        "capsule_manager.policy_alignment",
        "FAIL" if failed else "PASS",
        "capsule_security",
        (
            "Capsule Manager security policy is missing required deny-by-default controls."
            if failed
            else "Capsule Manager declares local-only Agent access, deny-by-default runtime policy, signed capsules and blocking gate statuses."
        ),
        evidence={"repo": str(repo), "failed": failed, "checks": checks},
        recommendation=(
            "Align Capsule Manager auth/runtime/security policies before release."
            if failed
            else None
        ),
        release_blocker=bool(failed),
    )


def run(cfg,report):
    root=Path(cfg["_target_root"])
    manifests=[]
    for name in ["frontend/package.json","backend/pyproject.toml","pyproject.toml"]:
        if (root/name).exists(): manifests.append(name)
    locks=[]
    for name in ["frontend/pnpm-lock.yaml","frontend/package-lock.json","frontend/yarn.lock","backend/uv.lock","uv.lock","poetry.lock","Pipfile.lock"]:
        if (root/name).exists(): locks.append(name)
    report.add("supply_chain.lockfiles.present","PASS" if locks else "WARN","supply_chain",
               "Dependency lockfiles detected." if locks else "No dependency lockfile detected.",evidence=locks or manifests,
               recommendation=None if locks else "Commit deterministic lockfiles for production dependency resolution.")
    workflow_findings=[]
    wf=root/".github"/"workflows"
    if wf.exists():
        for p in wf.glob("*.y*ml"):
            text=bounded_text(p,512*1024) or ""
            for i,line in enumerate(text.splitlines(),1):
                m=re.search(r"\buses:\s*([^\s#]+)@([^\s#]+)",line)
                if m and not SHA40.fullmatch(m.group(2)):
                    workflow_findings.append({"path":p.relative_to(root).as_posix(),"line":i,"uses":m.group(1),"ref":m.group(2)})
    report.add("supply_chain.github_actions.pinned","WARN" if workflow_findings else "PASS","supply_chain",
               "GitHub Actions references are not pinned to full commit SHAs." if workflow_findings else "No unpinned GitHub Actions references found in the bounded scan.",
               evidence=workflow_findings[:100] if workflow_findings else None,
               recommendation="For release-sensitive workflows, pin third-party actions to reviewed commit SHAs." if workflow_findings else None)
    mutable_images=[]
    weakly_pinned_images=[]
    supply_cfg=cfg.get("supply_chain",{}) if isinstance(cfg.get("supply_chain",{}),dict) else {}
    require_digests=bool(supply_cfg.get("require_immutable_image_digests",False))
    local_prefixes=tuple(str(x) for x in supply_cfg.get("local_image_prefixes",[]))
    for p,rel in iter_files(root,cfg,max_files=10000):
        if p.name in {"Dockerfile","docker-compose.yml","docker-compose.yaml","docker-compose.production.yml","docker-compose.production.yaml"} or "compose" in p.name.lower():
            text=bounded_text(p,512*1024)
            if not text:
                continue
            aliases=set()
            for i,line in enumerate(text.splitlines(),1):
                s=line.strip()
                value=None
                if s.startswith("FROM "):
                    parts=s.split()
                    if len(parts)>=2:
                        value=parts[1]
                        if value in aliases:
                            if len(parts)>=4 and parts[-2].upper()=="AS":
                                aliases.add(parts[-1])
                            continue
                        if len(parts)>=4 and parts[-2].upper()=="AS":
                            aliases.add(parts[-1])
                elif re.match(r"^\s*image:\s*",line):
                    value=s.split(":",1)[1].strip().strip("'\"")
                if not value:
                    continue
                # Locally-built release images cannot be digest-pinned in source; they are
                # instead bound by the signed Capsule Manager subject/image_digests.
                if local_prefixes and any(value.startswith(prefix) for prefix in local_prefixes):
                    continue
                record={"path":rel,"line":i,"image":value,"declaration":s[:220]}
                if value.startswith("${") or value.startswith("$"):
                    mutable_images.append({**record,"reason":"image reference is variable and cannot be proven immutable statically"})
                elif "@sha256:" not in value:
                    if require_digests:
                        mutable_images.append({**record,"reason":"release dependency is not pinned by sha256 digest"})
                    elif ":latest" in value or ("@" not in value and ":" not in value):
                        weakly_pinned_images.append(record)
    if require_digests:
        report.add("supply_chain.container_images.immutable","FAIL" if mutable_images else "PASS","supply_chain",
                   "One or more non-local release images are mutable or unresolved." if mutable_images else "All statically declared non-local release images are pinned by immutable sha256 digests.",
                   evidence=mutable_images[:100] if mutable_images else None,
                   recommendation="Pin external/base images as registry/repository@sha256:<digest>; bind locally-built image digests in the signed Capsule Manager release subject." if mutable_images else None,
                   release_blocker=bool(mutable_images))
    else:
        report.add("supply_chain.container_images.pinning","WARN" if weakly_pinned_images else "PASS","supply_chain",
                   "Some external container images use `latest` or no explicit version." if weakly_pinned_images else "No obvious `latest` or unversioned external container image found.",
                   evidence=weakly_pinned_images[:100] if weakly_pinned_images else None,
                   recommendation="Prefer immutable sha256 digests for release-sensitive images." if weakly_pinned_images else None)

    audits=cfg.get("supply_chain",{}).get("declared_audits",[])
    if not audits:
        report.add("supply_chain.declared_audits","SKIP","supply_chain","No dependency vulnerability audit command is declared.")
    for idx,a in enumerate(audits,1):
        aid=a.get("id",f"audit-{idx}")
        if not a.get("enabled",False):
            report.add(f"supply_chain.audit.{aid}","SKIP","supply_chain",f"Declared audit {aid} is disabled."); continue
        if not cfg.get("execution",{}).get("allow_declared_audits",False):
            report.add(f"supply_chain.audit.{aid}","BLOCKED","supply_chain",f"Declared audit {aid} is blocked by execution policy.",
                       recommendation="Enable execution.allow_declared_audits only after reviewing the exact command."); continue
        if a.get("network",True) and not cfg.get("execution",{}).get("allow_network",False):
            report.add(f"supply_chain.audit.{aid}","BLOCKED","supply_chain",f"Declared audit {aid} requires network access."); continue
        cwd=(root/a.get("cwd",".")).resolve(strict=False)
        if not cwd.is_relative_to(root):
            report.add(f"supply_chain.audit.{aid}","CONFIG_ERROR","supply_chain","Audit cwd escapes repository."); continue
        try:
            audit_argv=_validate_declared_audit_command(a.get("command"))
        except (TypeError, ValueError) as exc:
            report.add(
                f"supply_chain.audit.{aid}",
                "CONFIG_ERROR",
                "supply_chain",
                str(exc),
                recommendation="Declare only a reviewed, read-only package vulnerability audit command.",
            )
            continue
        r=run_command(audit_argv,cwd=cwd,timeout_seconds=int(a.get("timeout_seconds",300)))
        report.add(f"supply_chain.audit.{aid}","PASS" if r["exit_code"]==0 else "FAIL","supply_chain",
                   f"Declared dependency audit {aid} {'passed' if r['exit_code']==0 else 'failed'}.",
                   evidence={"exit_code":r["exit_code"],"stdout_tail":r["stdout_tail"][-4000:],"stderr_tail":r["stderr_tail"][-4000:]})
    _run_capsule_manager_alignment(cfg, report)
