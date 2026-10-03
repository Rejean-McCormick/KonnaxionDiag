from __future__ import annotations
import shutil, subprocess
from pathlib import Path
from diagcore.subprocesses import hidden_process_kwargs, diagnostic_subprocess_env, decode_process_output

def _git(root,*args):
    try:
        cp=subprocess.run(["git",*args],cwd=str(root),env=diagnostic_subprocess_env(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=False,timeout=20,check=False,
                          **hidden_process_kwargs())
        return cp.returncode,decode_process_output(cp.stdout).strip()
    except Exception:
        return 99,""

def git_info(root: Path):
    if not shutil.which("git"):
        return {"available":False,"repository":False}
    code,_=_git(root,"rev-parse","--is-inside-work-tree")
    if code!=0: return {"available":True,"repository":False}
    _,head=_git(root,"rev-parse","HEAD")
    _,branch=_git(root,"branch","--show-current")
    _,tracked=_git(root,"status","--short","--untracked-files=no")
    _,full=_git(root,"status","--short")
    return {"available":True,"repository":True,"head":head,"branch":branch,
            "tracked_status":tracked,"status":full}
