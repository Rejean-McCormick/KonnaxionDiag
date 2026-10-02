from __future__ import annotations
import re
from profiles.security.support.remote import run_script, RemoteBlocked

SCRIPT = r'''
set +e
echo "__SS__"
ss -H -lnt 2>/dev/null || netstat -lnt 2>/dev/null
echo "__UFW__"
UFW=""
for x in /usr/sbin/ufw /sbin/ufw "$(command -v ufw 2>/dev/null)"; do
  if [ -n "$x" ] && [ -x "$x" ]; then UFW="$x"; break; fi
done
if [ -n "$UFW" ]; then
  "$UFW" status verbose 2>&1
else
  echo "UFW_NOT_INSTALLED"
fi
'''

def public_binding(addr):
    a=addr.strip()
    if a.startswith("127.") or a.startswith("[::1]") or a.startswith("::1:") or a.startswith("localhost:"):
        return False
    return a.startswith("0.0.0.0:") or a.startswith("*:") or a.startswith("[::]:") or a.startswith(":::")

def extract_ports(text):
    rows=[]
    section=False
    for line in text.splitlines():
        if line.strip()=="__SS__":
            section=True
            continue
        if line.strip()=="__UFW__":
            break
        if not section or not line.strip():
            continue
        parts=line.split()
        local=None
        if len(parts)>=4 and parts[0].upper()=="LISTEN":
            local=parts[3]
        elif len(parts)>=4:
            local=parts[3]
        if not local:
            continue
        m=re.search(r':(\d+)$',local)
        if m:
            rows.append({"local":local,"port":int(m.group(1)),"public_bind":public_binding(local)})
    return rows

def run(cfg,report):
    try:
        r=run_script(cfg,SCRIPT,privileged=True,timeout_seconds=75)
    except RemoteBlocked as e:
        report.add("network.remote.listeners","BLOCKED","network",str(e))
        return
    if r["exit_code"]!=0:
        report.add("network.remote.listeners","INFRA_ERROR","network","Remote listener/firewall collection failed.",evidence=r)
        return
    rows=extract_ports(r["stdout_tail"])
    forbidden=set(int(x) for x in cfg.get("remote",{}).get("forbidden_public_ports",[]))
    bad=[x for x in rows if x["public_bind"] and x["port"] in forbidden]
    report.add("network.forbidden_public_bindings","FAIL" if bad else "PASS","network",
               "Forbidden internal ports are bound publicly." if bad else "No configured forbidden internal port is bound publicly.",
               evidence=bad or {"listeners":rows[:100]},
               recommendation="Bind internal services to localhost/private Docker networks and expose only the reverse proxy." if bad else None)
    ufw_text=r["stdout_tail"].split("__UFW__",1)[-1]
    if "UFW_NOT_INSTALLED" in ufw_text:
        report.add("network.ufw.active","FAIL" if cfg.get("remote",{}).get("require_ufw",True) else "WARN","firewall","UFW is not installed.")
    elif re.search(r"Status:\s*active",ufw_text,re.I):
        report.add("network.ufw.active","PASS","firewall","UFW reports active status.")
        deny_in=bool(re.search(r"Default:\s*deny\s*\(incoming\)",ufw_text,re.I))
        report.add("network.ufw.default_deny_incoming","PASS" if deny_in else "FAIL","firewall",
                   "UFW default incoming policy is deny." if deny_in else "UFW default incoming policy is not confirmed as deny.",
                   recommendation=None if deny_in else "Set the default incoming policy to deny before public exposure.")
        allowed_forbidden=[]
        for port in forbidden:
            if re.search(rf"(?m)^\s*{port}(?:/tcp)?\s+ALLOW\s+IN\b",ufw_text,re.I):
                allowed_forbidden.append(port)
        report.add("network.ufw.forbidden_allows","FAIL" if allowed_forbidden else "PASS","firewall",
                   "UFW explicitly allows forbidden internal ports." if allowed_forbidden else "UFW has no obvious explicit ALLOW rule for configured forbidden internal ports.",
                   evidence={"ports":sorted(allowed_forbidden)} if allowed_forbidden else None)
    elif "permission denied" in ufw_text.lower() or "password" in ufw_text.lower():
        report.add("network.ufw.active","BLOCKED","firewall","UFW status requires privileged evidence.",
                   recommendation="Allow a reviewed read-only privileged audit path or run SecurityDiag locally on the VPS as an administrative user.")
    else:
        report.add("network.ufw.active","FAIL" if cfg.get("remote",{}).get("require_ufw",True) else "WARN","firewall",
                   "UFW active status was not confirmed.",evidence=ufw_text[-2000:])
    report.metrics["listeners"]=rows
