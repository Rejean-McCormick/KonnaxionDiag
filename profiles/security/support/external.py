from __future__ import annotations
import socket, ssl, urllib.request, urllib.error
from datetime import datetime, timezone

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def resolve_host(host):
    rows=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    return sorted({r[4][0] for r in rows})

def probe_port(host,port,timeout=2.0):
    try:
        with socket.create_connection((host,int(port)),timeout=timeout):
            return True,None
    except Exception as e:
        return False,type(e).__name__

def tls_info(host,port=443,timeout=5.0):
    ctx=ssl.create_default_context()
    with socket.create_connection((host,port),timeout=timeout) as sock:
        with ctx.wrap_socket(sock,server_hostname=host) as ssock:
            cert=ssock.getpeercert()
            not_after=cert.get("notAfter")
            expiry=datetime.strptime(not_after,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
            return {"version":ssock.version(),"cipher":ssock.cipher()[0] if ssock.cipher() else None,
                    "expires_at":expiry.isoformat() if expiry else None,
                    "days_remaining":(expiry-datetime.now(timezone.utc)).days if expiry else None}

def fetch(url,timeout=8.0,follow_redirects=True):
    handlers=[] if follow_redirects else [NoRedirect()]
    opener=urllib.request.build_opener(*handlers)
    req=urllib.request.Request(url,headers={"User-Agent":"SecurityDiag/1.0"})
    try:
        with opener.open(req,timeout=timeout) as r:
            body=r.read(32768).decode("utf-8","replace")
            return {"status":r.status,"url":r.geturl(),"headers":dict(r.headers.items()),"body":body}
    except urllib.error.HTTPError as e:
        body=e.read(32768).decode("utf-8","replace")
        return {"status":e.code,"url":url,"headers":dict(e.headers.items()),"body":body}
