from __future__ import annotations
import re, shutil, subprocess, time
from pathlib import Path
from diagcore.utils import redact, tail_text

class RemoteBlocked(RuntimeError): pass
SAFE_HOST=re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
SAFE_USER=re.compile(r"^[A-Za-z0-9._-]+$")

def remote_ready(cfg):
    if not cfg.get("execution",{}).get("allow_network",False):
        return False,"Network execution is disabled."
    r=cfg.get("remote",{})
    if not r.get("enabled",False): return False,"Remote VPS checks are disabled."
    if not shutil.which("ssh"): return False,"ssh executable was not found."
    host=str(r.get("host","")).strip(); user=str(r.get("user","")).strip()
    if not host or not SAFE_HOST.fullmatch(host): return False,"remote.host is missing or unsafe."
    if not user or not SAFE_USER.fullmatch(user): return False,"remote.user is missing or unsafe."
    return True,""

def ssh_argv(cfg):
    ok,msg=remote_ready(cfg)
    if not ok: raise RemoteBlocked(msg)
    r=cfg["remote"]; host=str(r["host"]); user=str(r["user"]); port=int(r.get("port",22))
    argv=["ssh","-T","-p",str(port),"-o","BatchMode=yes",
          "-o",f"ConnectTimeout={int(r.get('connect_timeout_seconds',10))}",
          "-o",f"StrictHostKeyChecking={r.get('strict_host_key_checking','yes')}"]
    if r.get("identity_file"):
        argv += ["-i",str(Path(r["identity_file"]).expanduser())]
    if r.get("known_hosts_file"):
        argv += ["-o",f"UserKnownHostsFile={Path(r['known_hosts_file']).expanduser()}"]
    argv += [f"{user}@{host}"]
    return argv

def _script_bytes(script):
    """Return LF-only UTF-8 bytes so Windows cannot translate stdin to CRLF."""
    if isinstance(script, bytes):
        text=script.decode("utf-8","replace")
    else:
        text=str(script)
    text=text.replace("\r\n","\n").replace("\r","\n")
    return text.encode("utf-8")

def _decode(value):
    if isinstance(value,bytes):
        return value.decode("utf-8","replace")
    return value or ""

def run_script(cfg, script, *, privileged=False, timeout_seconds=90):
    r=cfg.get("remote",{})
    remote_user=str(r.get("user","")).strip()
    if privileged and remote_user != "root":
        if r.get("sudo_mode","none")!="noninteractive":
            raise RemoteBlocked("Privileged remote evidence requires remote.sudo_mode=noninteractive.")
        remote_cmd="sudo -n bash -s"
    else:
        # root is already privileged; do not require sudo to exist on minimal VPS images.
        remote_cmd="bash -s"
    argv=ssh_argv(cfg)+[remote_cmd]
    started=time.monotonic()
    try:
        # Send bytes, not text. On Windows, text-mode subprocess stdin converts LF to CRLF,
        # which makes bash receive stray '\r' characters and can break shell scripts.
        cp=subprocess.run(argv,input=_script_bytes(script),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=timeout_seconds,shell=False,check=False)
        out=_decode(cp.stdout); err=_decode(cp.stderr)
        return {"exit_code":cp.returncode,"timed_out":False,
                "duration_seconds":round(time.monotonic()-started,3),
                "stdout_tail":tail_text(redact(out),256*1024),
                "stderr_tail":tail_text(redact(err),128*1024)}
    except subprocess.TimeoutExpired as e:
        out=_decode(e.stdout); err=_decode(e.stderr)
        return {"exit_code":None,"timed_out":True,
                "duration_seconds":round(time.monotonic()-started,3),
                "stdout_tail":tail_text(redact(out),256*1024),
                "stderr_tail":tail_text(redact(err),128*1024)}
