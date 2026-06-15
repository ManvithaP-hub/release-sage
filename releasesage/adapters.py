"""Source adapters.

Live mode uses feedparser for rss/github_releases/arxiv kinds and a plain
GET + naive extraction for html kind (swap in trafilatura in production).
Fixture mode loads JSON so the pipeline is testable offline and in CI.

Every run records per-source telemetry (attempted / ok / items / error) —
observability is a first-class output, mirroring the one thing the reference
app did well.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

from .models import RawItem, Source


def load_sources(path: str | Path) -> list[Source]:
    import yaml
    data = yaml.safe_load(Path(path).read_text())
    return [Source(**s) for s in data["sources"]]


def fetch_live(source: Source, timeout: int = 20, limit: int = 25) -> list[RawItem]:
    if source.kind in ("rss", "github_releases", "arxiv") and source.feed:
        import feedparser
        parsed = feedparser.parse(source.feed)
        items = []
        for e in parsed.entries[:limit]:
            items.append(RawItem(
                source_id=source.id,
                title=getattr(e, "title", "").strip(),
                url=getattr(e, "link", source.url),
                summary=_strip_html(getattr(e, "summary", "") or getattr(e, "description", ""))[:2000],
                published=_entry_time(e),
            ))
        return items
    if source.kind == "html":
        # Minimal fallback: production should use trafilatura + per-source
        # CSS selectors. We fetch the page and emit a single "page changed"
        # item keyed by a content hash so diffs surface as updates.
        import hashlib
        import urllib.request
        req = urllib.request.Request(source.url, headers={"User-Agent": "brief-sage/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "ignore")
        digest = hashlib.sha256(body.encode()).hexdigest()[:12]
        return [RawItem(source_id=source.id,
                        title=f"{source.name} updated (content hash {digest})",
                        url=source.url,
                        summary=_strip_html(body)[:1500])]
    return []


def fetch_fixtures(source: Source, fixtures: dict) -> list[RawItem]:
    out = []
    for rec in fixtures.get(source.id, []):
        out.append(RawItem(source_id=source.id, **rec))
    return out


def collect(sources: Iterable[Source], fixture_path: str | None = None) -> tuple[list[tuple[Source, RawItem]], dict]:
    """Fetch all sources. Returns (items, telemetry)."""
    fixtures = None
    if fixture_path:
        fixtures = json.loads(Path(fixture_path).read_text())

    collected: list[tuple[Source, RawItem]] = []
    telemetry = {"attempted": 0, "succeeded": 0, "items": 0, "sources": {}}
    for src in sources:
        telemetry["attempted"] += 1
        t0 = time.time()
        try:
            items = fetch_fixtures(src, fixtures) if fixtures is not None else fetch_live(src)
            telemetry["succeeded"] += 1
            telemetry["sources"][src.id] = {"ok": True, "items": len(items),
                                            "ms": int((time.time() - t0) * 1000)}
            for it in items:
                collected.append((src, it))
            telemetry["items"] += len(items)
        except Exception as exc:  # noqa: BLE001 - per-source isolation is the point
            telemetry["sources"][src.id] = {"ok": False, "error": str(exc)[:200],
                                            "ms": int((time.time() - t0) * 1000)}
    return collected, telemetry


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", " ", text).replace("&nbsp;", " ").strip()


def _entry_time(entry) -> str | None:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", t)
    return None
