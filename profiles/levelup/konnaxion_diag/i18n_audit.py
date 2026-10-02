from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_TRANSLATION_CALL = r"(?:i18nT|t)\s*\("
_STYLE_TRANSLATION_RE = re.compile(rf"<style\s+jsx(?:\s+global)?\s*>\s*\{{\s*{_TRANSLATION_CALL}", re.IGNORECASE | re.MULTILINE)
_VALUE_OBJECT_TRANSLATION_RE = re.compile(rf"\bvalue\s*:\s*{_TRANSLATION_CALL}")
_VALUE_JSX_TRANSLATION_RE = re.compile(rf"\bvalue\s*=\s*\{{\s*{_TRANSLATION_CALL}")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CSS_VALUE_RE = re.compile(
    r"(?:^|[;{\s])(?:display|overflow|white-space|-webkit-|line-clamp|text-overflow|position|margin|padding|color|background)\s*:",
    re.IGNORECASE,
)
_SKIP_DIRS = {"node_modules", ".next", ".git", "artifacts", "coverage", "dist", "build", "_konnaxion_i18n_backups"}


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    leaves: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.update(_flatten(child, path))
        return leaves
    leaves[prefix] = value
    return leaves


def _load_catalog(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "catalog root must be a JSON object"
    return data, None


def _iter_source_files(frontend_dir: Path):
    for root in (frontend_dir / "app", frontend_dir / "components", frontend_dir / "context", frontend_dir / "global", frontend_dir / "routes", frontend_dir / "shared", frontend_dir / "src", frontend_dir / "widgets"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path


def audit_i18n(frontend_dir: Path) -> dict[str, Any]:
    locales_dir = frontend_dir / "i18n" / "locales"
    en_path = locales_dir / "en.json"
    fr_path = locales_dir / "fr.json"
    en, en_error = _load_catalog(en_path)
    fr, fr_error = _load_catalog(fr_path)

    report: dict[str, Any] = {
        "detected": en_path.exists() or fr_path.exists() or (frontend_dir / "context" / "LanguageContext.tsx").exists(),
        "paths": {"en": str(en_path), "fr": str(fr_path)},
        "catalog_errors": {},
        "en_leaf_count": 0,
        "fr_leaf_count": 0,
        "missing_in_en": [],
        "missing_in_fr": [],
        "blank_en": [],
        "blank_fr": [],
        "placeholder_mismatches": [],
        "identical_values": [],
        "css_like_catalog_values": [],
        "style_translation_calls": [],
        "translated_value_calls": [],
    }
    if en_error:
        report["catalog_errors"]["en"] = en_error
    if fr_error:
        report["catalog_errors"]["fr"] = fr_error
    if en is None or fr is None:
        return report

    en_flat = _flatten(en)
    fr_flat = _flatten(fr)
    report["en_leaf_count"] = len(en_flat)
    report["fr_leaf_count"] = len(fr_flat)
    en_keys, fr_keys = set(en_flat), set(fr_flat)
    report["missing_in_en"] = sorted(fr_keys - en_keys)
    report["missing_in_fr"] = sorted(en_keys - fr_keys)
    report["blank_en"] = sorted(k for k, v in en_flat.items() if not isinstance(v, str) or not v.strip())
    report["blank_fr"] = sorted(k for k, v in fr_flat.items() if not isinstance(v, str) or not v.strip())

    for key in sorted(en_keys & fr_keys):
        ev, fv = en_flat[key], fr_flat[key]
        if not isinstance(ev, str) or not isinstance(fv, str):
            continue
        ep = sorted(set(_PLACEHOLDER_RE.findall(ev)))
        fp = sorted(set(_PLACEHOLDER_RE.findall(fv)))
        if ep != fp:
            report["placeholder_mismatches"].append({"key": key, "en": ep, "fr": fp})
        if ev.strip() == fv.strip() and len(ev.strip()) > 2:
            report["identical_values"].append(key)
        if _CSS_VALUE_RE.search(ev) or _CSS_VALUE_RE.search(fv):
            report["css_like_catalog_values"].append(key)

    for path in _iter_source_files(frontend_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(frontend_dir).as_posix()
        for match in _STYLE_TRANSLATION_RE.finditer(text):
            report["style_translation_calls"].append({"file": rel, "line": text.count("\n", 0, match.start()) + 1})
        for regex in (_VALUE_OBJECT_TRANSLATION_RE, _VALUE_JSX_TRANSLATION_RE):
            for match in regex.finditer(text):
                report["translated_value_calls"].append({"file": rel, "line": text.count("\n", 0, match.start()) + 1})

    # deterministic / compact
    for name in ("css_like_catalog_values", "identical_values"):
        report[name] = sorted(set(report[name]))
    for name in ("style_translation_calls", "translated_value_calls"):
        seen = set()
        compact = []
        for item in report[name]:
            marker = (item["file"], item["line"])
            if marker not in seen:
                seen.add(marker)
                compact.append(item)
        report[name] = compact
    return report


I18N_BROWSER_PROBE_JS = r'''
const { chromium } = require('@playwright/test');
(async () => {
  const base = process.argv[1];
  const route = process.argv[2] || '/ekoh/dashboard?sidebar=ekoh';
  const url = new URL(route, base).toString();
  const browser = await chromium.launch({headless: true});
  const context = await browser.newContext();
  const page = await context.newPage();
  const locales = {fr: 'fr-CA', en: 'en-CA'};
  const aria = {fr: "Changer la langue de l’interface", en: 'Change interface language'};
  try {
    await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 60000});
    const root = page.locator('.ant-segmented').filter({has: page.locator('input[value="fr"]')}).filter({has: page.locator('input[value="en"]')}).first();
    await root.waitFor({state: 'visible', timeout: 30000});
    const initialHtml = (await page.locator('html').getAttribute('lang') || '').toLowerCase();
    const initial = initialHtml.startsWith('en') ? 'en' : 'fr';
    const target = initial === 'fr' ? 'en' : 'fr';
    const targetLabel = root.locator('label.ant-segmented-item').filter({hasText: target.toUpperCase()}).first();
    await targetLabel.click();
    await page.waitForFunction(expected => document.documentElement.lang === expected, locales[target], {timeout: 15000});
    await page.waitForFunction(expected => localStorage.getItem('konnaxion.language') === expected, target, {timeout: 15000});
    const switchedAria = await root.getAttribute('aria-label');
    if (switchedAria !== aria[target]) throw new Error(`aria-label did not switch: ${switchedAria}`);
    const cookies = await context.cookies();
    const cookie = cookies.find(c => c.name === 'konnaxion.language');
    if (!cookie || cookie.value !== target) throw new Error(`language cookie mismatch: ${cookie ? cookie.value : 'missing'}`);
    await page.reload({waitUntil: 'domcontentloaded', timeout: 60000});
    await page.waitForFunction(expected => document.documentElement.lang === expected, locales[target], {timeout: 15000});
    const persisted = await page.evaluate(() => localStorage.getItem('konnaxion.language'));
    if (persisted !== target) throw new Error(`language did not persist after reload: ${persisted}`);
    console.log('I18N_BROWSER_PROBE_OK ' + JSON.stringify({url, initial, target, htmlLang: locales[target], aria: switchedAria, storage: persisted, cookie: cookie.value}));
  } finally {
    await browser.close();
  }
})().catch(err => { console.error('I18N_BROWSER_PROBE_FAIL ' + (err && err.stack ? err.stack : err)); process.exit(1); });
'''.strip()


def browser_probe_command(base_url: str, route: str) -> list[str]:
    return ["node", "-e", I18N_BROWSER_PROBE_JS, base_url, route]
