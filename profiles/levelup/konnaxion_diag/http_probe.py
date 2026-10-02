from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(slots=True)
class HttpProbeResult:
    ok: bool
    status: int | None
    elapsed_ms: int
    content_type: str
    bytes_read: int
    error: str = ""


def probe(url: str, *, timeout: float = 8.0, allow_insecure_tls: bool = False) -> HttpProbeResult:
    context = ssl._create_unverified_context() if allow_insecure_tls else None
    request = urllib.request.Request(url, headers={"User-Agent": "LevelUpDiag-Konnaxion/1.0"})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(4096)
            return HttpProbeResult(
                ok=200 <= int(response.status) < 500,
                status=int(response.status),
                elapsed_ms=int((time.monotonic() - started) * 1000),
                content_type=str(response.headers.get("Content-Type", "")),
                bytes_read=len(body),
            )
    except urllib.error.HTTPError as exc:
        return HttpProbeResult(
            ok=200 <= int(exc.code) < 500,
            status=int(exc.code),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            content_type=str(exc.headers.get("Content-Type", "")) if exc.headers else "",
            bytes_read=0,
            error=str(exc),
        )
    except Exception as exc:
        return HttpProbeResult(
            ok=False,
            status=None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            content_type="",
            bytes_read=0,
            error=f"{type(exc).__name__}: {exc}",
        )
