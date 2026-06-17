"""Authoritative advisory enrichment via OSV (osv.dev).

This is the accuracy layer. Heuristic keyword scoring answers "does this look
like a security item?" — useful, but it cannot answer the question that
actually decides whether you act: **is the version I run actually affected?**

OSV (https://osv.dev) is a free, no-key vulnerability database that aggregates
GHSA, CVE, and ecosystem advisories with machine-readable *affected version
ranges* and CVSS vectors. Given a component, its ecosystem, and the version you
run, this module asks OSV directly and returns a precise verdict:

    affected      — your version falls inside a known-vulnerable range
    not_affected  — advisories exist but your version is outside their ranges
    unknown       — OSV has no data (fall back to heuristic, flagged as such)

When `affected`, we attach the advisory id (CVE/GHSA), CVSS score/severity, and
the fixed version so the briefing can say "patch to X" instead of guessing.

Network note: this calls api.osv.dev at runtime. If the call fails (offline,
rate limit), enrichment degrades to `unknown` and the heuristic result stands —
the pipeline never crashes on a failed lookup.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Map our components to the OSV ecosystem + package name OSV indexes them under.
# Go modules are indexed by their module path; GitHub Actions / others differ.
# Extend alongside discover.py::CATALOG.
OSV_PACKAGES: dict[str, list[dict]] = {
    "argocd": [{"ecosystem": "Go", "name": "github.com/argoproj/argo-cd/v2"},
               {"ecosystem": "Go", "name": "github.com/argoproj/argo-cd"}],
    "keda": [{"ecosystem": "Go", "name": "github.com/kedacore/keda/v2"}],
    "external-secrets": [{"ecosystem": "Go", "name": "github.com/external-secrets/external-secrets"}],
    "kyverno": [{"ecosystem": "Go", "name": "github.com/kyverno/kyverno"}],
    "cert-manager": [{"ecosystem": "Go", "name": "github.com/cert-manager/cert-manager"}],
}


@dataclass
class OSVVerdict:
    status: str                       # affected | not_affected | unknown
    advisory_id: str = ""             # CVE/GHSA id of the matching advisory
    cvss_score: float | None = None
    severity: str = ""                # critical | high | moderate | low
    fixed_version: str = ""
    summary: str = ""
    source: str = "osv.dev"
    all_ids: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Version comparison (PEP 440-ish semantic ordering, tolerant of v-prefix)
# --------------------------------------------------------------------------

def parse_version(v: str) -> tuple:
    v = (v or "").lstrip("vV").split("+")[0].split("-")[0]
    parts = []
    for p in v.split("."):
        parts.append(int(p) if p.isdigit() else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _cmp(a: str, b: str) -> int:
    pa, pb = parse_version(a), parse_version(b)
    return (pa > pb) - (pa < pb)


def version_in_ranges(version: str, ranges: list[dict]) -> tuple[bool, str]:
    """OSV 'ranges' use events: introduced / fixed / last_affected.
    Returns (is_affected, fixed_version_if_any).

    Semantics per OSV spec: a version is affected if it is >= an 'introduced'
    event and < the next 'fixed' event (or <= 'last_affected').
    """
    fixed_seen = ""
    for r in ranges:
        events = r.get("events", [])
        introduced = None
        for ev in events:
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev:
                fixed = ev["fixed"]
                fixed_seen = fixed
                lo = introduced or "0"
                if (lo == "0" or _cmp(version, lo) >= 0) and _cmp(version, fixed) < 0:
                    return True, fixed
                introduced = None
            elif "last_affected" in ev:
                la = ev["last_affected"]
                lo = introduced or "0"
                if (lo == "0" or _cmp(version, lo) >= 0) and _cmp(version, la) <= 0:
                    return True, ""
                introduced = None
        # range with an introduced but no fixed/last_affected => affected from intro on
        if introduced is not None and (introduced == "0" or _cmp(version, introduced) >= 0):
            return True, ""
    return False, fixed_seen


def _extract_severity(vuln: dict) -> tuple[float | None, str]:
    """Pull a CVSS score from an OSV vuln record."""
    score = None
    for sev in vuln.get("severity", []) or []:
        s = sev.get("score", "")
        # OSV severity scores are CVSS vector strings; many tools also expose numeric
        if isinstance(s, (int, float)):
            score = float(s)
        elif isinstance(s, str) and s.replace(".", "", 1).isdigit():
            score = float(s)
    # database_specific sometimes carries a numeric/severity label
    dbs = vuln.get("database_specific", {}) or {}
    label = (dbs.get("severity") or "").lower()
    if not label and score is not None:
        label = ("critical" if score >= 9 else "high" if score >= 7
                 else "moderate" if score >= 4 else "low")
    return score, label


# --------------------------------------------------------------------------
# Query
# --------------------------------------------------------------------------

def query_osv(ecosystem: str, name: str, version: str, timeout: int = 12) -> list[dict]:
    body = json.dumps({"version": version, "package": {"ecosystem": ecosystem, "name": name}}).encode()
    req = urllib.request.Request(OSV_QUERY_URL, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "release-sage/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode())
    return data.get("vulns", []) or []


def assess(component_id: str, version: str) -> OSVVerdict:
    """Authoritative verdict for a component@version. Network call; degrades
    to status='unknown' on any failure so callers never crash."""
    pkgs = OSV_PACKAGES.get(component_id)
    if not pkgs or not version or version.upper() in ("UNKNOWN", "REVIEW"):
        return OSVVerdict(status="unknown",
                          summary="No OSV package mapping or version for this component.")
    try:
        vulns = []
        for p in pkgs:
            vulns = query_osv(p["ecosystem"], p["name"], version)
            if vulns:
                break
    except Exception as exc:  # noqa: BLE001
        return OSVVerdict(status="unknown", summary=f"OSV lookup failed: {exc}")

    if not vulns:
        # OSV queried by version returns only advisories affecting THAT version,
        # so an empty list means this version is not known-affected.
        return OSVVerdict(status="not_affected",
                          summary=f"OSV has no advisories affecting {version}.")

    return verdict_from_vulns(vulns, version)


def verdict_from_vulns(vulns: list[dict], version: str) -> OSVVerdict:
    """Pure function (unit-testable offline): turn OSV vuln records into a verdict."""
    ids = [v.get("id", "") for v in vulns if v.get("id")]
    best: OSVVerdict | None = None
    for v in vulns:
        affected_ranges = []
        for a in v.get("affected", []) or []:
            affected_ranges += a.get("ranges", []) or []
        is_aff, fixed = version_in_ranges(version, affected_ranges) if affected_ranges else (True, "")
        if not is_aff:
            continue
        score, sev = _extract_severity(v)
        cand = OSVVerdict(status="affected", advisory_id=v.get("id", ""),
                          cvss_score=score, severity=sev, fixed_version=fixed,
                          summary=v.get("summary", "")[:300], all_ids=ids)
        # keep the highest-severity matching advisory
        if best is None or (cand.cvss_score or 0) > (best.cvss_score or 0):
            best = cand
    if best:
        return best
    return OSVVerdict(status="not_affected", all_ids=ids,
                      summary=f"Advisories exist but none affect {version}.")
