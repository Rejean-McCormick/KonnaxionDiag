from __future__ import annotations
import json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECRET_RX=[
 re.compile(r"(?i)(DJANGO_SECRET_KEY|POSTGRES_PASSWORD|DATABASE_URL|API[_-]?KEY|ACCESS[_-]?TOKEN|PRIVATE[_-]?KEY)\s*[:=]\s*([^\s,;]+)"),
 re.compile(r"(?i)(password|secret|token|private[_-]?key|api[_-]?key|authorization|cookie)(\s*[:=]\s*)([^\s\"';]+)"),
 re.compile(r"(?i)((?:postgres|postgresql|redis)://[^:/\s]+:)[^@\s]+@"),
 re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
 re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
 re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]
SENSITIVE_CONFIG_KEYS={"django_secret_key","postgres_password","database_url","api_key","access_token","private_key","password","token","bearer_token","agent_token","signing_private_key"}
SENSITIVE_CONFIG_SUFFIXES=("_password","_secret","_secret_key","_api_key","_access_token","_private_key","_bearer_token","_token")

def utc_now(): return datetime.now(timezone.utc).isoformat()
def local_now(): return datetime.now().astimezone().isoformat(timespec="seconds")
def read_json(path:Path): return json.loads(path.read_text(encoding="utf-8-sig"))
def write_json(path:Path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    os.replace(tmp,path)

def redact(text:str,replacement="[REDACTED]"):
    if not text: return text
    out=text
    for rx in SECRET_RX:
        if rx.groups>=3:
            out=rx.sub(lambda m:f"{m.group(1)}{m.group(2)}{replacement}",out)
        elif rx.groups>=2:
            out=rx.sub(lambda m:f"{m.group(1)}={replacement}",out)
        else: out=rx.sub(replacement,out)
    return out

def _sensitive_config_key(key:Any)->bool:
    name=str(key).strip().lower().replace("-","_")
    return name in SENSITIVE_CONFIG_KEYS or any(name.endswith(s) for s in SENSITIVE_CONFIG_SUFFIXES)

def redact_data(value:Any,replacement="[REDACTED]",*,_key:Any=None):
    if _key is not None and _sensitive_config_key(_key): return replacement
    if isinstance(value,dict):
        if str(_key).strip().lower().replace("-","_") in {"environment","env"}: return {k:replacement for k in value}
        return {k:redact_data(v,replacement,_key=k) for k,v in value.items()}
    if isinstance(value,(list,tuple)): return [redact_data(v,replacement) for v in value]
    if isinstance(value,str): return redact(value,replacement)
    return value

def tail_text(text:str,limit_bytes:int):
    raw=(text or "").encode("utf-8","replace")
    return (text or "") if len(raw)<=limit_bytes else raw[-limit_bytes:].decode("utf-8","replace")

def safe_rel(root:Path,path:Path):
    try:return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except Exception:return str(path)

def parse_bool(value): return value if isinstance(value,bool) else str(value).strip().lower() in {"1","true","yes","on"}
