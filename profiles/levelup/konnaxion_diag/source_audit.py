from __future__ import annotations
import os
import re
from pathlib import Path

FORBIDDEN = ("/api/home/", "/api/konsultations/", "/api/reseau/", "/api/profil/")
MUTATION = re.compile(r"\b(method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|\.(?:post|put|patch|delete)\s*\()", re.I)
API_LITERAL = re.compile(r"['\"](/api/[A-Za-z0-9_./{}?&=:-]+)['\"]")
ROUTE_REG = re.compile(r"register_(?:required|optional)\(\s*router\s*,\s*['\"]([^'\"]+)['\"]")

WORLD_OWNED_API_PREFIXES = (
    "/api/ethikos/",
    "/api/deliberate/",
    "/api/teambuilder/",
    "/api/keenkonnect/",
    "/api/konnected/",
    "/api/kreative/",
    "/api/kollective/",
    "/api/v1/ekoh/",
    "/api/v1/smart-vote/",
    "/api/reports/",
    "/api/admin/moderation/",
    "/api/admin/konsensus-config/",
)


_EXCLUDED_DIRS={'.git','node_modules','.next','dist','build','coverage','artifacts','.venv','venv','__pycache__','.cache'}

def _walk_files(root: Path, names: set[str] | None = None, suffixes: tuple[str, ...] = ()):
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        base=Path(dirpath)
        for name in filenames:
            if names is not None and name not in names: continue
            if suffixes and not name.endswith(suffixes): continue
            yield base/name

def _files(root: Path):
    yield from _walk_files(root, suffixes=('.ts','.tsx','.js','.jsx'))

def backend_prefixes(backend: Path) -> set[str]:
    prefixes=set()
    for p in _walk_files(backend, names={'urls.py'}):
        try: text=p.read_text(encoding='utf-8', errors='ignore')
        except OSError: continue
        prefixes.update('/api/'+x.strip('/') for x in ROUTE_REG.findall(text))
    return prefixes


def _strip_js_comments(text: str) -> str:
    """Remove // and /* */ comments while preserving string/template contents."""
    out: list[str] = []
    i = 0
    n = len(text)
    quote: str | None = None
    escaped = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if quote is not None:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in {"'", '"', '`'}:
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and nxt == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if ch == '/' and nxt == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                if text[i] == '\n':
                    out.append('\n')
                i += 1
            i = min(n, i + 2)
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _uses_csrf_safe_client(code: str) -> bool:
    if any(token in code for token in (
        'X-CSRFToken', 'X-XSRF-TOKEN', 'xsrfHeaderName',
        'apiFetch(', 'apiPost(', 'apiPut(', 'apiPatch(', 'apiDelete(',
    )):
        return True
    if "services/_request" in code or "@/services/_request" in code:
        return True
    return False



def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def auth_contract_audit(frontend: Path, backend: Path) -> dict:
    """Static audit of Konnaxion's standalone-first common-auth contract."""
    base_settings = _read_text(backend / "config/settings/base.py")
    prod_settings = _read_text(backend / "config/settings/production.py")
    urls = _read_text(backend / "config/urls.py")
    models = _read_text(backend / "konnaxion/users/models.py")
    adapters = _read_text(backend / "konnaxion/users/adapters.py")
    requirements = _read_text(backend / "requirements/base.txt")
    frontend_package = _read_text(frontend / "package.json")
    frontend_prod_env = _read_text(frontend / "env.production.example")

    auth0_paths = [
        frontend / "lib/auth0.ts",
        frontend / "components/auth0-components/index.tsx",
        frontend / "app/providers/AuthProvider.tsx",
    ]
    auth0_residue = [
        str(path.relative_to(frontend))
        for path in auth0_paths
        if path.exists()
    ]
    if "@auth0/" in frontend_package:
        auth0_residue.append("package.json:@auth0")

    return {
        "allauth_oidc_provider": (
            "allauth.socialaccount.providers.openid_connect" in base_settings
            and '"openid_connect"' in base_settings
        ),
        "oidc_uid_sub": bool(
            re.search(r'["\']uid_field["\']\s*:\s*["\']sub["\']', base_settings)
        ),
        "oidc_optional": bool(
            re.search(r"COMMON_OIDC_ENABLED\s*=\s*env\.bool\(", base_settings)
            and re.search(r"SOCIALACCOUNT_ONLY\s*=\s*False", base_settings)
        ),
        "email_auto_connect_disabled": bool(
            re.search(r"SOCIALACCOUNT_EMAIL_AUTHENTICATION\s*=\s*False", base_settings)
            and re.search(
                r"SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT\s*=\s*False",
                base_settings,
            )
        ),
        "accounts_route": (
            'path("accounts/", include("allauth.urls"))' in urls
            or "path('accounts/', include('allauth.urls'))" in urls
        ),
        "legacy_token_endpoint": bool(
            re.search(r"\bobtain_auth_token\b|api/auth-token", urls, re.I)
        ),
        "interactive_policy": (
            "def can_interactive_login" in models
            and "user.can_interactive_login" in adapters
        ),
        "csrf_browser_contract": bool(
            re.search(r"CSRF_COOKIE_SECURE\s*=\s*True", prod_settings)
            and re.search(r"CSRF_COOKIE_HTTPONLY\s*=\s*False", prod_settings)
            and re.search(
                r'CSRF_COOKIE_NAME\s*=\s*["\']csrftoken["\']',
                prod_settings,
            )
        ),
        "admin_allauth": bool(
            re.search(r"DJANGO_ADMIN_FORCE_ALLAUTH\s*=\s*True", prod_settings)
        ),
        "same_origin_api": bool(
            re.search(
                r"^\s*NEXT_PUBLIC_API_BASE\s*=\s*/api\s*$",
                frontend_prod_env,
                re.M,
            )
        ),
        "requirements_oidc": bool(
            re.search(
                r"django-allauth\[[^\]]*socialaccount[^\]]*\]",
                requirements,
                re.I,
            )
        ),
        "auth0_residue": sorted(set(auth0_residue)),
    }


def audit(frontend: Path, backend: Path) -> dict:
    double=[]; forbidden=[]; mutations=[]; endpoints=set(); world_owned_unscoped=[]
    for p in _files(frontend):
        try: text=p.read_text(encoding='utf-8', errors='ignore')
        except OSError: continue
        rel=str(p.relative_to(frontend))
        code=_strip_js_comments(text)
        for ep in API_LITERAL.findall(code):
            endpoint = ep.split('?')[0]
            endpoints.add(endpoint)
            if '/api/api/' in ep: double.append((rel,ep))
            if ep.startswith(FORBIDDEN): forbidden.append((rel,ep))
            if not endpoint.startswith('/api/w/') and endpoint.startswith(WORLD_OWNED_API_PREFIXES):
                world_owned_unscoped.append((rel, endpoint))
        if MUTATION.search(code) and ('credentials' in code or 'apiFetch' in code or 'fetch(' in code or '.post(' in code or '.put(' in code or '.patch(' in code or '.delete(' in code):
            if not _uses_csrf_safe_client(code):
                mutations.append(rel)
    prefixes=backend_prefixes(backend)
    unmapped=[]
    for ep in sorted(endpoints):
        if ep.startswith(FORBIDDEN): continue
        if prefixes and not any(ep==p or ep.startswith(p.rstrip('/')+'/') for p in prefixes):
            unmapped.append(ep)
    return {'double_api':double,'forbidden':forbidden,'csrf_risk_files':sorted(set(mutations)),'unmapped':unmapped,'world_owned_unscoped':sorted(set(world_owned_unscoped)),'backend_prefixes':sorted(prefixes),'frontend_endpoints':sorted(endpoints),'auth_contract':auth_contract_audit(frontend, backend)}
