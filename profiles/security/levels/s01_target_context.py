from __future__ import annotations
import platform, shutil
from pathlib import Path
from profiles.security.support.vcs import git_info
from diagcore.commands import run_command

def run(cfg, report):
    target=Path(cfg["_target_root"]); control=Path(cfg["_control_root"])
    report.add("target.root.exists","PASS" if target.is_dir() else "CONFIG_ERROR","target",
               "Target repository root is available.",path=target)
    gi=git_info(target)
    if gi.get("repository"):
        report.add("target.git.detected","PASS","vcs","Git repository detected.",
                   evidence={"head":gi.get("head"),"branch":gi.get("branch"),"tracked_dirty":bool(gi.get("tracked_status"))})
        rel=control.relative_to(target).as_posix()
        r=run_command(["git","check-ignore","-q","--",rel],cwd=target,timeout_seconds=10,capture_limit_kb=8)
        report.add("target.control_dir.ignored","PASS" if r["exit_code"]==0 else "WARN","vcs",
                   ".konnaxiondiag evidence is ignored by Git." if r["exit_code"]==0 else ".konnaxiondiag evidence is not ignored by Git.",
                   evidence={"control_dir":rel},recommendation=None if r["exit_code"]==0 else f"Add {rel}/ to .gitignore.")
    else:
        report.add("target.git.detected","WARN","vcs","No Git repository detected.",evidence=gi)
    report.add("runtime.local.platform","PASS","environment","Local runtime identified.",
               evidence={"system":platform.system(),"release":platform.release()})
    report.add("security.phase.declared","PASS","context",f"Security phase is {cfg.get('phase','unspecified')}.")
    net=bool(cfg.get("execution",{}).get("allow_network",False))
    report.add("security.network.execution","PASS" if not net else "WARN","safety",
               "Network execution is disabled by default." if not net else "Network execution is enabled for remote/external security checks.",
               recommendation=None if not net else "Keep remote/external targets explicit and trusted.")
    r=cfg.get("remote",{})
    report.add("security.remote.target","PASS" if r.get("enabled") else "SKIP","context",
               f"Remote target configured: {r.get('user','')}@{r.get('host','')}:{r.get('port',22)}" if r.get("enabled") else "Remote VPS checks are disabled.")
