from __future__ import annotations
from profiles.security.support.external import resolve_host, probe_port, tls_info, fetch

def run(cfg,report):
    if not cfg.get("execution",{}).get("allow_network",False):
        report.add("external.network.enabled","BLOCKED","external_surface","Network execution is disabled.")
        return
    ext=cfg.get("external",{})
    if not ext.get("enabled",False):
        report.add("external.target.enabled","BLOCKED","external_surface","External security target is disabled.")
        return
    host=str(ext.get("host","")).strip()
    if not host:
        report.add("external.target.host","CONFIG_ERROR","external_surface","external.host is empty.")
        return
    try:
        ips=resolve_host(host)
        report.add("external.dns.resolve","PASS","external_surface","Public hostname resolves.",evidence={"host":host,"addresses":ips})
    except Exception as e:
        report.add("external.dns.resolve","FAIL","external_surface","Public hostname did not resolve.",evidence={"error":type(e).__name__})
        return
    timeout=float(ext.get("timeout_seconds",3))
    checks={}
    for port in sorted(set(ext.get("required_open_ports",[])+ext.get("administrative_ports",[])+ext.get("forbidden_ports",[]))):
        ok,err=probe_port(host,int(port),timeout)
        checks[int(port)]={"open":ok,"error":err}
    required=[p for p in ext.get("required_open_ports",[]) if not checks.get(int(p),{}).get("open")]
    forbidden=[p for p in ext.get("forbidden_ports",[]) if checks.get(int(p),{}).get("open")]
    report.add("external.required_ports.open","FAIL" if required else "PASS","external_surface",
               "Required public ports are unreachable." if required else "Required public ports are reachable.",
               evidence={"missing":required,"probes":checks})
    report.add("external.forbidden_ports.closed","FAIL" if forbidden else "PASS","external_surface",
               "Forbidden internal ports are reachable from this external vantage point." if forbidden else "Configured forbidden ports are closed from this external vantage point.",
               evidence={"open_forbidden":forbidden,"probes":checks},
               recommendation="Close provider firewall/security-group rules and remove public container/process bindings." if forbidden else None)
    try:
        ti=tls_info(host,int(ext.get("https_port",443)),timeout=max(timeout,5))
        days=ti.get("days_remaining")
        verdict="FAIL" if days is not None and days<0 else ("WARN" if days is not None and days<30 else "PASS")
        report.add("external.tls.certificate",verdict,"tls","TLS certificate and hostname validation succeeded.",evidence=ti,
                   recommendation="Renew certificate before expiry." if verdict=="WARN" else None)
        version=ti.get("version","")
        report.add("external.tls.protocol","PASS" if version in {"TLSv1.2","TLSv1.3"} else "WARN","tls",
                   f"Negotiated TLS protocol is {version}.",evidence={"version":version,"cipher":ti.get("cipher")})
    except Exception as e:
        report.add("external.tls.certificate","FAIL","tls","TLS handshake/certificate validation failed.",evidence={"error":type(e).__name__})
    try:
        h=fetch(f"http://{host}:{int(ext.get('http_port',80))}/",timeout=max(timeout,5),follow_redirects=False)
        loc=h.get("headers",{}).get("Location","")
        redirect=h.get("status") in {301,302,307,308} and loc.lower().startswith("https://")
        report.add("external.http.redirect_https","PASS" if redirect else "FAIL","tls",
                   "HTTP redirects to HTTPS." if redirect else "HTTP did not clearly redirect to HTTPS.",
                   evidence={"status":h.get("status"),"location":loc})
    except Exception as e:
        report.add("external.http.redirect_https","FAIL","tls","HTTP redirect probe failed.",evidence={"error":type(e).__name__})
    try:
        h=fetch(f"https://{host}:{int(ext.get('https_port',443))}/",timeout=max(timeout,8),follow_redirects=True)
        headers={k.lower():v for k,v in h.get("headers",{}).items()}
        status=h.get("status",0)
        report.add("external.https.response","PASS" if 200<=status<500 else "FAIL","external_surface",
                   f"HTTPS root returned HTTP {status}.",evidence={"final_url":h.get("url"),"status":status})
        hsts=bool(headers.get("strict-transport-security"))
        report.add("external.headers.hsts","PASS" if hsts else ("FAIL" if ext.get("require_hsts",True) else "WARN"),"headers",
                   "HSTS header is present." if hsts else "HSTS header is missing.")
        missing=[]
        for name in ext.get("recommended_headers",[]):
            if name.lower() not in headers:
                missing.append(name)
        report.add("external.headers.recommended","WARN" if missing else "PASS","headers",
                   "Recommended browser security headers are missing." if missing else "Configured recommended browser security headers are present.",
                   evidence={"missing":missing} if missing else None)
        server=headers.get("server","")
        report.add("external.headers.server_banner","WARN" if any(ch.isdigit() for ch in server) else "PASS","headers",
                   "Server header may expose version information." if any(ch.isdigit() for ch in server) else "Server header does not obviously expose a version.",
                   evidence={"server":server or None})
    except Exception as e:
        report.add("external.https.response","FAIL","external_surface","HTTPS application probe failed.",evidence={"error":type(e).__name__})
    try:
        probe=fetch(f"https://{host}:{int(ext.get('https_port',443))}/__securitydiag_nonexistent_7f41a9/",timeout=max(timeout,8),follow_redirects=True)
        body=(probe.get("body") or "")[:32768].lower()
        debug=("you're seeing this error because you have debug = true" in body or "django version" in body and "traceback" in body)
        report.add("external.django.debug_page","FAIL" if debug else "PASS","application_security",
                   "A Django debug-style error page was detected." if debug else "No obvious Django debug page was exposed by the invalid-path probe.")
    except Exception as e:
        report.add("external.django.debug_page","WARN","application_security","Could not complete invalid-path debug exposure probe.",evidence={"error":type(e).__name__})
    report.metrics["port_probes"]=checks
