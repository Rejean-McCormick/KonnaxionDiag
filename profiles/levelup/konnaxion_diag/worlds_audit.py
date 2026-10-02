from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


HOST_FILES = {
    "frontend_worlds_lib": "frontend/lib/worlds.ts",
    "frontend_world_context": "frontend/context/WorldContext.tsx",
    "frontend_world_switcher": "frontend/components/worlds/WorldSwitcher.tsx",
    "frontend_header": "frontend/components/layout-components/Header.tsx",
    "frontend_main_layout": "frontend/components/layout-components/MainLayout.tsx",
    "frontend_menu": "frontend/components/layout-components/Menu.tsx",
    "frontend_next_middleware": "frontend/middleware.ts",
    "frontend_next_config": "frontend/next.config.ts",
    "frontend_suite_tests": "frontend/routes/suites.test.ts",
    "frontend_world_tests": "frontend/lib/__tests__/worlds.test.ts",
    "backend_world_urls": "backend/config/world_urls.py",
    "backend_world_api_router": "backend/config/world_api_router.py",
    "backend_urls": "backend/config/urls.py",
    "backend_settings": "backend/config/settings/base.py",
    "backend_world_adapters": "backend/config/world_adapters.py",
    "backend_konnaxion_init": "backend/konnaxion/__init__.py",
    "host_ownership_guard": "scripts/check_worlds_ownership.py",
}

ENGINE_FILES = {
    "engine_pyproject": "backend/pyproject.toml",
    "engine_standalone_settings": "backend/worlds_config/settings.py",
    "engine_init": "backend/konnaxion/worlds/__init__.py",
    "engine_models": "backend/konnaxion/worlds/models.py",
    "engine_runtime": "backend/konnaxion/worlds/runtime.py",
    "engine_db": "backend/konnaxion/worlds/db.py",
    "engine_middleware": "backend/konnaxion/worlds/middleware.py",
    "engine_urls": "backend/konnaxion/worlds/urls.py",
    "engine_runtime_urls": "backend/konnaxion/worlds/runtime_urls.py",
    "engine_health": "backend/konnaxion/worlds/services/health.py",
    "engine_tasks": "backend/konnaxion/worlds/services/tasks.py",
    "engine_universe_service": "backend/konnaxion/worlds/services/universes.py",
    "engine_builder": "backend/konnaxion/worlds/services/builder.py",
    "engine_snapshots": "backend/konnaxion/worlds/services/snapshots.py",
    "engine_build_command": "backend/konnaxion/worlds/management/commands/worlds_build.py",
    "engine_queue_command": "backend/konnaxion/worlds/management/commands/worlds_queue_catalog.py",
    "engine_universe_migration": "backend/konnaxion/worlds/migrations/0004_universes.py",
    "engine_multiworld_test": "backend/konnaxion/worlds/tests/test_multiworld_isolation.py",
    "engine_universe_test": "backend/konnaxion/worlds/tests/test_universes.py",
    "engine_strict_routing_test": "backend/konnaxion/worlds/tests/test_strict_routing.py",
    "engine_boundary_guard": "scripts/check_repo_boundaries.py",
    "engine_universe_spec": "docs/Technical-Reference/Worlds/20_UNIVERSES.md",
    "engine_ai_lock": "docs/Technical-Reference/Worlds/AI_LOCK.yaml",
}

# Kept for compatibility with callers/tests that imported the old constant.
CORE_FILES = {**HOST_FILES, **{f"worlds_repo::{k}": v for k, v in ENGINE_FILES.items()}}


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _has_all(text: str, needles: tuple[str, ...]) -> bool:
    return all(needle in text for needle in needles)


def _bool_default(settings_text: str, name: str, value: bool) -> bool:
    literal = "True" if value else "False"
    pattern = re.compile(
        rf"{re.escape(name)}\s*=\s*env\.bool\(\s*[\"']{re.escape(name)}[\"']\s*,\s*default\s*=\s*{literal}\s*,?\s*\)",
        re.S,
    )
    return bool(pattern.search(settings_text))


def _infer_worlds_repo(frontend: Path, backend: Path) -> Path:
    host_root = frontend.parent if frontend.parent == backend.parent else backend.parent
    return host_root.parent / "Konnaxion_Worlds"


def audit_worlds(frontend: Path, backend: Path, worlds_repo: Path | None = None) -> dict[str, Any]:
    """Audit the split Konnaxion host + Konnaxion_Worlds engine architecture.

    Konnaxion owns the browser shell and product adapters. Konnaxion_Worlds owns
    the Universe/World/WorldRelease engine, migrations and canonical spec.
    """
    host_root = frontend.parent if frontend.parent == backend.parent else backend.parent
    engine_repo = (worlds_repo or _infer_worlds_repo(frontend, backend)).resolve(strict=False)
    engine_backend = engine_repo / "backend"

    host_files = {name: host_root / relative for name, relative in HOST_FILES.items()}
    engine_files = {name: engine_repo / relative for name, relative in ENGINE_FILES.items()}
    host_exists = {name: path.is_file() for name, path in host_files.items()}
    engine_exists = {name: path.is_file() for name, path in engine_files.items()}

    detected = any(
        host_exists.get(key, False)
        for key in ("frontend_worlds_lib", "frontend_world_context", "host_ownership_guard")
    ) or any(
        engine_exists.get(key, False)
        for key in ("engine_models", "engine_runtime", "engine_universe_spec")
    )

    missing = [f"Konnaxion/{HOST_FILES[name]}" for name, present in host_exists.items() if not present]
    missing.extend(
        f"Konnaxion_Worlds/{ENGINE_FILES[name]}" for name, present in engine_exists.items() if not present
    )

    # Product/engine ownership must be mutually exclusive, not duplicated.
    forbidden_host_paths = (
        host_root / "backend" / "konnaxion" / "worlds",
        host_root / "docs" / "Technical-Reference" / "Worlds",
    )
    forbidden_engine_paths = (
        engine_repo / "frontend",
    )
    engine_namespace = engine_repo / "backend" / "konnaxion"
    engine_namespace_extras = []
    if engine_namespace.is_dir():
        engine_namespace_extras = [
            child
            for child in engine_namespace.iterdir()
            if child.name not in {"worlds", "__pycache__"}
        ]
    forbidden_present = [
        str(path)
        for path in (*forbidden_host_paths, *forbidden_engine_paths, *engine_namespace_extras)
        if path.exists()
    ]

    worlds_ts = _text(host_files["frontend_worlds_lib"])
    context_tsx = _text(host_files["frontend_world_context"])
    switcher_tsx = _text(host_files["frontend_world_switcher"])
    header_tsx = _text(host_files["frontend_header"])
    main_layout_tsx = _text(host_files["frontend_main_layout"])
    menu_tsx = _text(host_files["frontend_menu"])
    next_middleware_ts = _text(host_files["frontend_next_middleware"])
    next_config_ts = _text(host_files["frontend_next_config"])
    suite_tests_ts = _text(host_files["frontend_suite_tests"])
    world_tests_ts = _text(host_files["frontend_world_tests"])

    host_world_urls_py = _text(host_files["backend_world_urls"])
    host_world_router_py = _text(host_files["backend_world_api_router"])
    host_urls_py = _text(host_files["backend_urls"])
    host_settings_py = _text(host_files["backend_settings"])
    host_adapters_py = _text(host_files["backend_world_adapters"])
    host_init_py = _text(host_files["backend_konnaxion_init"])
    host_guard_py = _text(host_files["host_ownership_guard"])

    engine_pyproject = _text(engine_files["engine_pyproject"])
    standalone_settings_py = _text(engine_files["engine_standalone_settings"])
    engine_init = _text(engine_files["engine_init"])
    models_py = _text(engine_files["engine_models"])
    runtime_py = _text(engine_files["engine_runtime"])
    db_py = _text(engine_files["engine_db"])
    middleware_py = _text(engine_files["engine_middleware"])
    engine_urls_py = _text(engine_files["engine_urls"])
    health_py = _text(engine_files["engine_health"])
    tasks_py = _text(engine_files["engine_tasks"])
    metadata_sources = "\n".join(_text(engine_files[name]) for name in (
        "engine_builder", "engine_snapshots", "engine_build_command", "engine_queue_command"
    ))
    migration_py = _text(engine_files["engine_universe_migration"])
    multiworld_test_py = _text(engine_files["engine_multiworld_test"])
    universe_test_py = _text(engine_files["engine_universe_test"])
    strict_test_py = _text(engine_files["engine_strict_routing_test"])
    engine_guard_py = _text(engine_files["engine_boundary_guard"])
    universe_spec_md = _text(engine_files["engine_universe_spec"])
    ai_lock_yaml = _text(engine_files["engine_ai_lock"])

    auth_index = host_settings_py.find("django.contrib.auth.middleware.AuthenticationMiddleware")
    worlds_index = host_settings_py.find("konnaxion.worlds.middleware.WorldRouteMiddleware")

    frontend_contracts = {
        "url_is_universe_world_authority": _has_all(
            worlds_ts,
            (
                "parseWorldPath",
                "getUniverseKeyFromPathname",
                "getWorldKeyFromPathname",
                "stripWorldPrefix",
                "withWorldPath",
                "UNIVERSE_WORLD_PATH_RE",
            ),
        ) and _has_all(context_tsx, ("usePathname", "routeUniverseKey", "getWorldKeyFromPathname(pathname)")),
        "hard_universe_world_switch": _has_all(
            context_tsx,
            ("switchUniverse", "switchWorld", "window.location.assign", "switchWorldPath"),
        ),
        "switch_preserves_query_hash": _has_all(
            context_tsx,
            ("window.location.search", "window.location.hash", "window.location.assign"),
        ),
        "stale_universe_world_release_guard": _has_all(
            worlds_ts,
            (
                "StaleUniverseResponseError",
                "StaleWorldResponseError",
                "StaleWorldReleaseError",
                "assertCurrentWorldResponse",
                "kxUniverse",
                "kxWorldReleaseId",
            ),
        ),
        "api_scope_helpers": _has_all(
            worlds_ts,
            ("isGlobalApiPath", "scopeApiPath", "scopeBrowserApiUrl", "GLOBAL_API_PREFIXES"),
        ) and "u/${universeKey}/w/${worldKey}" in worlds_ts,
        "websocket_scope_helpers": _has_all(
            worlds_ts,
            ("scopeWorldWebSocketPath", "resolveWorldWebSocketUrl", "u/${universeKey}/w/${worldKey}", "/ws/${context}"),
        ),
        "next_api_safety_net": _has_all(
            next_middleware_ts,
            (
                "context.universeKey",
                "context.worldKey",
                "isGlobalApiPath",
                "NextResponse.rewrite",
                "/api/u/${context.universeKey}/w/${context.worldKey}/",
            ),
        ),
        "next_ui_world_carryover": _has_all(
            next_middleware_ts,
            ("isUiCarryoverCandidate", "withWorldPath", "NextResponse.redirect"),
        ),
        "next_universe_world_rewrite": _has_all(
            next_config_ts,
            (
                "source: '/u/:universe/w/:world'",
                "source: '/u/:universe/w/:world/:path*'",
                "source: '/w/:world'",
                "destination: '/:path*'",
            ),
        ),
        "universe_world_switcher_in_header": _has_all(
            switcher_tsx,
            ("k-universe-select", "k-world-select", "switchUniverse", "switchWorld"),
        ) and "WorldSwitcher" in header_tsx and "<WorldSwitcher" in header_tsx,
        "sidebar_uses_app_path": _has_all(main_layout_tsx, ("useWorld", "appPath", "detectSuite(appPath"))
        and _has_all(menu_tsx, ("useWorld", "appPath", "href(route.path)")),
        "sidebar_cross_module_tests": _has_all(
            suite_tests_ts,
            ("/w/demo-alpha/konsensus", "ethikos", "sidebar override"),
        ),
        "universe_world_helper_tests": _has_all(
            world_tests_ts,
            (
                "canonical and legacy World routes",
                "Universe/World API scoping",
                "scopeWorldWebSocketPath",
                "/u/christianity/w/theology",
            ),
        ),
    }

    host_contracts = {
        "worlds_app_registered": "konnaxion.worlds.apps.WorldsConfig" in host_settings_py,
        "middleware_after_auth": auth_index >= 0 and worlds_index > auth_index,
        "control_and_universe_world_routes": _has_all(
            host_urls_py,
            ("api/control/", "api/u/", "/w/", "config.world_urls"),
        ),
        "namespace_package_extension": _has_all(host_init_py, ("extend_path", "__path__")),
        "host_domain_adapters": _has_all(
            host_settings_py,
            (
                "KONNAXION_WORLDS_SCENARIO_IMPORTER",
                "KONNAXION_WORLDS_FIXTURE_LOADER",
                "KONNAXION_WORLDS_FIXTURE_CHECKSUM_PROVIDER",
            ),
        ) and _has_all(
            host_adapters_py,
            ("import_world_scenario", "load_world_auxiliary_fixture", "world_auxiliary_fixture_checksum"),
        ),
        "world_router_reuses_canonical_routes": _has_all(
            host_world_router_py,
            ("canonical_urlpatterns", "_GLOBAL_ROUTE_NAME_PREFIXES", "urlpatterns"),
        ),
        "data_plane_default_off": _bool_default(host_settings_py, "KONNAXION_WORLDS_DATA_PLANE_ENABLED", False),
        "scoped_api_default_on": _bool_default(host_settings_py, "KONNAXION_WORLDS_ENFORCE_SCOPED_API", True),
        "data_plane_fail_closed_503": _has_all(
            host_world_urls_py,
            ("WORLD_DATA_PLANE_NOT_READY", "status=503", "KONNAXION_WORLDS_DATA_PLANE_ENABLED"),
        ),
        "runtime_always_mounted": 'path("", include("konnaxion.worlds.runtime_urls"))' in host_world_urls_py,
    }

    engine_contracts = {
        "package_is_external_installable_engine": _has_all(
            engine_pyproject,
            ('name = "konnaxion-worlds"', 'include = ["konnaxion.worlds*"]', "namespaces = true"),
        ),
        "standalone_scoped_api_default_on": _has_all(
            standalone_settings_py,
            (
                'KONNAXION_WORLDS_ENFORCE_SCOPED_API = _bool(',
                '"KONNAXION_WORLDS_ENFORCE_SCOPED_API", True',
            ),
        ) and "KONNAXION_WORLDS_STRICT_ROUTING" not in standalone_settings_py,
        "architecture_metadata_current": (
            '"architecture_lock": "KX-UNIVERSES-1"' in metadata_sources
            and '"architecture_lock": "KX-WORLDS-1"' not in metadata_sources
        ),
        "architecture_lock": "KX-UNIVERSES-1" in engine_init and "KX-UNIVERSES-1" in ai_lock_yaml,
        "universe_data_model": _has_all(
            models_py,
            (
                "class Universe(",
                "class UniverseMembership(",
                "class WorldRelation(",
                "class WorldPublication(",
                "class WorldSubscription(",
                "universe = models.ForeignKey",
            ),
        ),
        "universe_migration": _has_all(
            migration_py,
            ("Universe", "UniverseMembership", "WorldRelation", "WorldPublication", "WorldSubscription"),
        ),
        "immutable_runtime_context": _has_all(
            runtime_py,
            (
                "@dataclass(frozen=True",
                "ContextVar",
                "WorldContextRequired",
                "WorldContextConflict",
                "universe_id",
                "universe_key",
                "world_id",
                "release_id",
            ),
        ),
        "transaction_local_search_path": _has_all(
            db_py,
            ("SET LOCAL search_path", "transaction.atomic", "ekoh_schema", "domain_schema"),
        ),
        "response_context_headers": _has_all(
            middleware_py,
            (
                "X-Konnaxion-Universe",
                "X-Konnaxion-World",
                "X-Konnaxion-World-Release",
                "X-Konnaxion-World-Release-Id",
                "X-Konnaxion-World-Dirty",
            ),
        ),
        "canonical_and_legacy_runtime_routing": _has_all(
            middleware_py,
            ("_UNIVERSE_WORLD_ROUTE_RE", "universe_key", "_LEGACY_WORLD_ROUTE_RE", "resolve_world_runtime"),
        ),
        "universe_control_api": _has_all(
            engine_urls_py,
            (
                'path("universes/"',
                "relations/",
                "publications/",
                "subscriptions/",
                'path("worlds/"',
            ),
        ),
        "health_reports_universe_lock": _has_all(
            health_py,
            ("KX-UNIVERSES-1", "Universe", '"universes"', '"worlds"'),
        ),
        "multiworld_isolation_test": _has_all(
            multiworld_test_py,
            ("Universe.objects.create", "domain_schema !=", "ekoh_schema !="),
        ),
        "universe_invariant_tests": _has_all(
            universe_test_py,
            (
                "test_runtime_resolves_universe_world_release_tuple",
                "test_relation_cannot_cross_universes",
                "test_subscription_cannot_cross_universes",
                "test_publication_release_must_belong_to_source_world",
            ),
        ),
        "strict_route_tests": _has_all(
            strict_test_py,
            ("KONNAXION_WORLDS_ENFORCE_SCOPED_API=True", "WORLD_REQUIRED"),
        ),
        "universe_spec_present": _has_all(
            universe_spec_md,
            ("Universe", "WorldRelation", "WorldPublication", "KX-UNIVERSES-1"),
        ),
    }

    ownership_contracts = {
        "host_does_not_vendor_engine": not (host_root / "backend" / "konnaxion" / "worlds").exists(),
        "host_does_not_vendor_canonical_spec": not (host_root / "docs" / "Technical-Reference" / "Worlds").exists(),
        "host_ownership_guard": _has_all(
            host_guard_py,
            ("Konnaxion_Worlds", "backend", "konnaxion", "worlds", "Technical-Reference"),
        ),
        "engine_does_not_vendor_product_frontend": not (engine_repo / "frontend").exists(),
        "engine_namespace_is_worlds_only": not engine_namespace_extras,
        "engine_boundary_guard": _has_all(
            engine_guard_py,
            (
                "Konnaxion_Worlds repository boundary",
                "ENGINE_ALLOWED_CHILDREN",
                'ROOT / "frontend"',
                "backend/konnaxion contains only worlds",
            ),
        ),
    }

    jobs_contracts = {
        "release_pinned_task_scope": _has_all(
            tasks_py,
            ("world_task_scope", "world_id", "release_id", "select_for_update", "STATUS_CURRENT"),
        )
    }

    all_contracts = {
        **{f"frontend.{key}": value for key, value in frontend_contracts.items()},
        **{f"host.{key}": value for key, value in host_contracts.items()},
        **{f"engine.{key}": value for key, value in engine_contracts.items()},
        **{f"ownership.{key}": value for key, value in ownership_contracts.items()},
        **{f"jobs.{key}": value for key, value in jobs_contracts.items()},
    }

    return {
        "detected": detected,
        "architecture_lock": "KX-UNIVERSES-1",
        "host_root": str(host_root),
        "worlds_repo": str(engine_repo),
        "worlds_backend": str(engine_backend),
        "required_files": {
            **{f"host.{name}": str(path) for name, path in host_files.items()},
            **{f"engine.{name}": str(path) for name, path in engine_files.items()},
        },
        "missing_files": missing,
        "forbidden_present": forbidden_present,
        "frontend": frontend_contracts,
        "host": host_contracts,
        # Keep backend as an alias for old LevelUpDiag report consumers.
        "backend": engine_contracts,
        "engine": engine_contracts,
        "ownership": ownership_contracts,
        "jobs": jobs_contracts,
        "failed_contracts": [name for name, ok in all_contracts.items() if not ok],
        "ok": detected and not missing and not forbidden_present and all(all_contracts.values()),
    }


def summarize_worlds_audit(report: dict[str, Any]) -> str:
    return json.dumps(
        {
            "architecture_lock": report.get("architecture_lock"),
            "detected": report.get("detected"),
            "worlds_repo": report.get("worlds_repo"),
            "missing_files": report.get("missing_files", []),
            "forbidden_present": report.get("forbidden_present", []),
            "failed_contracts": report.get("failed_contracts", []),
        },
        sort_keys=True,
    )


def _http_json(url: str, *, timeout: float = 5.0) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "LevelUpDiag-Konnaxion-Universes/3.4"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(65536)
            status = int(response.status)
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read(65536)
        status = int(exc.code)
        headers = {str(k).lower(): str(v) for k, v in exc.headers.items()} if exc.headers else {}
    except Exception as exc:
        return {
            "status": None,
            "json": None,
            "headers": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    try:
        payload = json.loads(raw.decode("utf-8", errors="replace")) if raw else None
    except json.JSONDecodeError:
        payload = None
    return {
        "status": status,
        "json": payload,
        "headers": headers,
        "error": "",
    }


def _backend_api_base(config: Any) -> str | None:
    section = config.get("konnaxion", {})
    if not isinstance(section, dict):
        return None
    worlds = section.get("worlds", {})
    if isinstance(worlds, dict):
        explicit = worlds.get("backend_api_base_url")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.rstrip("/") + "/"
    urls = section.get("local_urls", [])
    if isinstance(urls, list):
        for value in urls:
            if isinstance(value, str) and "/api" in value:
                base = value.split("/api", 1)[0].rstrip("/")
                return f"{base}/api/"
    return None


def probe_worlds_control_plane(config: Any, paths: dict[str, Any]) -> dict[str, Any]:
    """Read-only probes for the Universe/World control and runtime planes."""
    import os
    from urllib.parse import urljoin

    section = config.get("konnaxion", {})
    section = section if isinstance(section, dict) else {}
    worlds_cfg = section.get("worlds", {})
    worlds_cfg = worlds_cfg if isinstance(worlds_cfg, dict) else {}
    base = _backend_api_base(config)
    required = os.environ.get("LEVELUPDIAG_CAMPAIGN", "") == "world-switch"
    expected_lock = str(worlds_cfg.get("architecture_lock", "KX-UNIVERSES-1"))
    timeout = float(worlds_cfg.get("http_timeout_seconds", 5) or 5)
    findings: list[dict[str, Any]] = []

    if not base:
        findings.append({
            "id": "kx.worlds.runtime.control-live",
            "severity": "FAIL" if required else "WARN",
            "message": "Cannot derive the local backend /api base URL for Universe/World probes.",
            "recommendation": "Configure konnaxion.worlds.backend_api_base_url or konnaxion.local_urls.",
        })
        return {"base_url": None, "findings": findings}

    for suffix, kind in (("control/health/live/", "liveness"), ("control/health/ready/", "readiness")):
        url = urljoin(base, suffix)
        result = _http_json(url, timeout=timeout)
        payload = result.get("json") if isinstance(result.get("json"), dict) else {}
        ok = (
            result.get("status") == 200
            and payload.get("architecture_lock") == expected_lock
            and payload.get("kind") == kind
            and payload.get("ok") is True
        )
        findings.append({
            "id": f"kx.worlds.runtime.control-{kind}",
            "severity": "PASS" if ok else ("FAIL" if required else "WARN"),
            "message": f"Universe/World control-plane {kind} probe {'passed' if ok else 'failed'}.",
            "path": url,
            "evidence": json.dumps({
                "status": result.get("status"),
                "architecture_lock": payload.get("architecture_lock"),
                "kind": payload.get("kind"),
                "ok": payload.get("ok"),
                "error": result.get("error"),
                "errors": payload.get("errors"),
            }, sort_keys=True),
            "recommendation": "Start the local PostgreSQL-backed runtime and repair KX-UNIVERSES-1 readiness before qualification." if not ok else None,
        })

    catalog_url = urljoin(base, "control/universes/")
    catalog_result = _http_json(catalog_url, timeout=timeout)
    catalog_payload = catalog_result.get("json")
    catalog_ok = catalog_result.get("status") == 200 and isinstance(catalog_payload, list)
    findings.append({
        "id": "kx.worlds.runtime.universe-catalog",
        "severity": "PASS" if catalog_ok else ("FAIL" if required else "WARN"),
        "message": "Universe catalog endpoint is readable." if catalog_ok else "Universe catalog endpoint probe failed.",
        "path": catalog_url,
        "evidence": json.dumps({
            "status": catalog_result.get("status"),
            "count": len(catalog_payload) if isinstance(catalog_payload, list) else None,
            "error": catalog_result.get("error"),
        }, sort_keys=True),
    })

    universe_key = str(worlds_cfg.get("runtime_probe_universe_key", "")).strip()
    world_key = str(worlds_cfg.get("runtime_probe_world_key", "")).strip()
    if not world_key:
        findings.append({
            "id": "kx.worlds.runtime.world",
            "severity": "SKIP",
            "message": "No runtime probe World configured; control-plane and Universe catalog probes completed without mutating the catalog.",
            "recommendation": "Set konnaxion.worlds.runtime_probe_universe_key + runtime_probe_world_key after promoting a local test World.",
        })
        return {"base_url": base, "universe_key": universe_key or None, "world_key": None, "findings": findings}

    runtime_suffix = (
        f"u/{universe_key}/w/{world_key}/runtime/" if universe_key else f"w/{world_key}/runtime/"
    )
    runtime_url = urljoin(base, runtime_suffix)
    runtime_result = _http_json(runtime_url, timeout=timeout)
    runtime_payload = runtime_result.get("json") if isinstance(runtime_result.get("json"), dict) else {}
    headers = runtime_result.get("headers", {}) if isinstance(runtime_result.get("headers"), dict) else {}
    release = runtime_payload.get("release") if isinstance(runtime_payload.get("release"), dict) else {}
    world = runtime_payload.get("world") if isinstance(runtime_payload.get("world"), dict) else {}
    universe = runtime_payload.get("universe") if isinstance(runtime_payload.get("universe"), dict) else {}
    payload_universe = str(universe.get("key", ""))
    effective_universe = universe_key or payload_universe
    runtime_ok = (
        runtime_result.get("status") == 200
        and runtime_payload.get("architecture_lock") == expected_lock
        and str(world.get("key", "")).lower() == world_key.lower()
        and bool(payload_universe)
        and (not universe_key or payload_universe.lower() == universe_key.lower())
        and release.get("id") is not None
        and str(headers.get("x-konnaxion-universe", "")).lower() == payload_universe.lower()
        and str(headers.get("x-konnaxion-world", "")).lower() == world_key.lower()
        and str(headers.get("x-konnaxion-world-release-id", "")) == str(release.get("id"))
    )
    findings.append({
        "id": "kx.worlds.runtime.world",
        "severity": "PASS" if runtime_ok else "FAIL",
        "message": f"Universe/World runtime/header probe {'passed' if runtime_ok else 'failed'} for {effective_universe or '?'}/{world_key}.",
        "path": runtime_url,
        "evidence": json.dumps({
            "status": runtime_result.get("status"),
            "universe": payload_universe,
            "world": world.get("key"),
            "release_id": release.get("id"),
            "header_universe": headers.get("x-konnaxion-universe"),
            "header_world": headers.get("x-konnaxion-world"),
            "header_release_id": headers.get("x-konnaxion-world-release-id"),
            "error": runtime_result.get("error"),
        }, sort_keys=True),
        "recommendation": "Use the canonical /api/u/<universe>/w/<world>/runtime/ route and ensure middleware emits matching Universe/World/Release headers." if not runtime_ok else None,
    })

    data_plane_path = str(worlds_cfg.get("data_plane_probe_path", "")).strip().lstrip("/")
    if runtime_ok and data_plane_path:
        data_prefix = f"u/{payload_universe}/w/{world_key}/" if payload_universe else f"w/{world_key}/"
        data_url = urljoin(base, f"{data_prefix}{data_plane_path}")
        data_result = _http_json(data_url, timeout=timeout)
        capabilities = runtime_payload.get("capabilities") if isinstance(runtime_payload.get("capabilities"), dict) else {}
        enabled = capabilities.get("data_plane_enabled") is True
        data_payload = data_result.get("json") if isinstance(data_result.get("json"), dict) else {}
        if enabled:
            data_ok = data_result.get("status") != 503
            message = "Enabled World data plane does not return the fail-closed 503 sentinel."
        else:
            data_ok = data_result.get("status") == 503 and data_payload.get("error") == "WORLD_DATA_PLANE_NOT_READY"
            message = "Disabled World data plane returns the expected fail-closed 503 sentinel."
        findings.append({
            "id": "kx.worlds.runtime.data-plane-state",
            "severity": "PASS" if data_ok else "FAIL",
            "message": message if data_ok else "World data-plane runtime behavior does not match advertised capabilities.",
            "path": data_url,
            "evidence": json.dumps({
                "data_plane_enabled": enabled,
                "status": data_result.get("status"),
                "error_code": data_payload.get("error"),
            }, sort_keys=True),
        })

    return {
        "base_url": base,
        "universe_key": payload_universe or universe_key or None,
        "world_key": world_key,
        "findings": findings,
    }
