from __future__ import annotations
from profiles.security.support.remote import run_script, RemoteBlocked

SCRIPT = r'''
set +e
SSHD=""
for x in /usr/sbin/sshd /sbin/sshd "$(command -v sshd 2>/dev/null)"; do
  if [ -n "$x" ] && [ -x "$x" ]; then SSHD="$x"; break; fi
done
if [ -z "$SSHD" ]; then
  echo "__NO_SSHD__"
  exit 0
fi
"$SSHD" -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|allowusers|x11forwarding|allowtcpforwarding|maxauthtries) '
'''

def parse(text):
    d={}
    for line in text.splitlines():
        p=line.strip().split(None,1)
        if len(p)==2:
            d[p[0].lower()]=p[1].strip()
    return d

def run(cfg,report):
    try:
        r=run_script(cfg,SCRIPT,privileged=True,timeout_seconds=60)
    except RemoteBlocked as e:
        report.add("ssh.effective_config","BLOCKED","ssh",str(e))
        return
    if "__NO_SSHD__" in r["stdout_tail"]:
        report.add("ssh.effective_config","BLOCKED","ssh","sshd executable was not found on remote host.")
        return
    if r["exit_code"]!=0:
        report.add("ssh.effective_config","INFRA_ERROR","ssh","Could not collect effective sshd configuration.",evidence=r)
        return
    d=parse(r["stdout_tail"])
    if not d:
        report.add("ssh.effective_config","BLOCKED","ssh","Effective sshd configuration returned no usable fields.")
        return
    report.add("ssh.root_login.disabled","PASS" if d.get("permitrootlogin")=="no" else "FAIL","ssh",
               "Root SSH login is disabled." if d.get("permitrootlogin")=="no" else f"PermitRootLogin is {d.get('permitrootlogin','unknown')}.",
               recommendation="Set PermitRootLogin no.")
    report.add("ssh.password_auth.disabled","PASS" if d.get("passwordauthentication")=="no" else "FAIL","ssh",
               "SSH password authentication is disabled." if d.get("passwordauthentication")=="no" else f"PasswordAuthentication is {d.get('passwordauthentication','unknown')}.",
               recommendation="Set PasswordAuthentication no.")
    kbd=d.get("kbdinteractiveauthentication",d.get("challengeresponseauthentication"))
    report.add("ssh.keyboard_interactive.disabled","PASS" if kbd=="no" else "FAIL","ssh",
               "Keyboard-interactive authentication is disabled." if kbd=="no" else f"Keyboard-interactive authentication is {kbd or 'unknown'}.",
               recommendation="Set KbdInteractiveAuthentication no.")
    report.add("ssh.pubkey.enabled","PASS" if d.get("pubkeyauthentication")=="yes" else "FAIL","ssh",
               "Public-key authentication is enabled." if d.get("pubkeyauthentication")=="yes" else "Public-key authentication was not confirmed.")
    expected=cfg.get("remote",{}).get("user")
    allow=d.get("allowusers","")
    report.add("ssh.allowusers.restricted","PASS" if allow and expected in allow.split() else "WARN","ssh",
               "AllowUsers explicitly includes the configured deployment user." if allow and expected in allow.split() else "AllowUsers does not explicitly restrict SSH to the configured deployment user.",
               evidence={"allowusers":allow or None})
    report.add("ssh.x11.disabled","PASS" if d.get("x11forwarding")=="no" else "WARN","ssh",
               "X11 forwarding is disabled." if d.get("x11forwarding")=="no" else "X11 forwarding is enabled or unknown.")
    report.add("ssh.tcp_forwarding.disabled","PASS" if d.get("allowtcpforwarding")=="no" else "WARN","ssh",
               "TCP forwarding is disabled." if d.get("allowtcpforwarding")=="no" else f"AllowTcpForwarding is {d.get('allowtcpforwarding','unknown')}.")
    try:
        maxtries=int(d.get("maxauthtries","99"))
    except ValueError:
        maxtries=99
    report.add("ssh.max_auth_tries","PASS" if maxtries<=3 else "WARN","ssh",f"MaxAuthTries is {maxtries}.",
               recommendation=None if maxtries<=3 else "Consider MaxAuthTries 3.")
    report.metrics["effective"]=d
