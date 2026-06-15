"""Inventory matching and operational urgency.

This is what makes release-sage different from a generic release radar: an item
only matters if it touches a component you actually run, and urgency is scored
against the version you're on, not in the abstract.

Two scores feed the gate:
  relevance  — does this touch my stack, and by how much? (0-100)
  urgency    — how fast do I need to act? security + breaking, equal weight.
"""
from __future__ import annotations

import re

from .models import Classification, RawItem, Source

# Equal weighting of security and breaking-change urgency, per the chosen rubric.
_SECURITY_MARKERS = ["cve-", "ghsa-", "vulnerability", "security advisory",
                     "rce", "privilege escalation", "exploit", "patch", "cvss"]
_SEVERITY = {"critical": 95, "high": 80, "moderate": 55, "medium": 55, "low": 30}
_BREAKING_MARKERS = ["breaking change", "breaking:", "deprecat", "removed",
                     "no longer", "must migrate", "incompatible", "action required",
                     "drop support", "end of support", "eol"]


def load_inventory(path: str) -> dict:
    import yaml
    from pathlib import Path
    data = yaml.safe_load(Path(path).read_text())
    by_id = {}
    for c in data.get("components", []) + data.get("platforms", []):
        by_id[c["id"]] = c
    return by_id


def _semver(text: str) -> tuple[int, int, int] | None:
    # Require an x.y.z (or vX.Y) that looks like a real version tag, and skip
    # pre-release/build suffixes. Avoids grabbing stray numbers out of prose.
    m = re.search(r"(?:^|[\sv])(\d+)\.(\d+)(?:\.(\d+))?(?![\d.])", text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def relevance(raw: RawItem, source: Source, inventory: dict) -> tuple[int, str | None, str]:
    """Returns (relevance_score, matched_component_id, reason).

    A source declares which component it watches, but the *content* must also
    correspond to that component — a feed can carry items about other projects
    (forks, related releases). We verify the name/repo actually appears, so
    'cert-manager release seen on a watched feed' does not match kyverno.
    """
    comp_id = getattr(source, "component", None)
    text = f"{raw.title} {raw.summary}".lower()

    def _mentions(comp: dict, cid: str) -> bool:
        needles = [comp["name"].lower(), comp.get("repo", "").lower(),
                   comp.get("repo", "").split("/")[-1].lower(), cid]
        return any(n and n in text for n in needles if n)

    # source binding, but confirmed by content
    if comp_id and comp_id in inventory:
        comp = inventory[comp_id]
        if _mentions(comp, comp_id):
            return 90, comp_id, f"confirmed {comp['name']} item"
        # bound feed but the item is about something else — check the rest of inv
    # scan whole inventory by mention
    for cid, comp in inventory.items():
        if _mentions(comp, cid):
            return 80, cid, f"mentions {comp['name']}"
    return 0, None, "no inventory component matched"


def version_gap(raw: RawItem, comp: dict) -> str:
    """Human note on how far the release is ahead of the running version."""
    have = _semver(comp.get("version", ""))
    rel = _semver(raw.title) or _semver(raw.summary)
    if not have or not rel:
        return ""
    if rel <= have:
        return f"You are on {comp['version']}; this is not newer."
    if rel[0] > have[0]:
        return f"Major version jump from {comp['version']} → {'.'.join(map(str, rel))} (plan migration)."
    if rel[1] > have[1]:
        return f"Minor upgrade available from {comp['version']} → {'.'.join(map(str, rel))}."
    return f"Patch available from {comp['version']} → {'.'.join(map(str, rel))}."


def classify_release(raw: RawItem, source: Source, inventory: dict, policy: dict) -> Classification:
    """Domain classifier for release/advisory items (heuristic mode).

    LLM mode can still be layered on later; for operational data the
    deterministic signals (severity strings, semver, breaking markers) are
    actually quite reliable, unlike news substance.
    """
    text = f"{raw.title} {raw.summary}".lower()
    rel_score, comp_id, rel_reason = relevance(raw, source, inventory)
    comp = inventory.get(comp_id, {}) if comp_id else {}

    # Security ONLY if it comes from an advisory feed, OR carries a real
    # CVE/GHSA identifier. Loose words like "patch" or "security" in ordinary
    # release notes must NOT trigger a security alarm — false alarms are the
    # one thing this tool must avoid.
    has_cve_id = bool(re.search(r"\b(cve-\d{4}-\d+|ghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", text))
    is_security = source.kind == "github_security" or has_cve_id
    is_breaking = any(m in text for m in _BREAKING_MARKERS)

    # urgency: security severity and breaking impact, equal weight, take the max
    sec_urgency = 0
    if is_security:
        sec_urgency = 70
        for sev, val in _SEVERITY.items():
            if sev in text:
                sec_urgency = max(sec_urgency, val)
    brk_urgency = 75 if is_breaking else 0
    urgency = max(sec_urgency, brk_urgency)

    gap = version_gap(raw, comp) if comp else ""
    already_covered = gap.startswith("You are on") and "not newer" in gap
    if already_covered:
        urgency = min(urgency, 20)  # already on this version

    # category / signal label in ops terms
    if is_security:
        category, label = "security", "patch_now" if urgency >= 80 else "security_review"
    elif is_breaking:
        category, label = "breaking_change", "upgrade_planning"
    elif rel_score > 0 and not already_covered:
        category, label = "release", "routine_update"
    else:
        category, label = "release", "noise"

    # substance reused by the generic gate = operational relevance.
    # A routine release you're already on, or that's not newer, is not actionable.
    if label == "noise" or already_covered:
        substance = 0
    else:
        substance = rel_score
        if is_security or is_breaking:
            substance = min(100, substance + 10)

    what = f"{source.name}: {raw.title}."
    why = _why(category, comp.get("name", "your stack"), gap)
    takeaway = _takeaway(label, comp.get("name", "the component"))

    return Classification(
        category=category, signal_label=label,
        audiences=["platform_sre", "devops"],
        substance=substance, novelty=85,
        hype_risk=10,  # primary release/advisory feeds; not vendor hype
        urgency=urgency,
        what_happened=what, why_it_matters=why, builder_takeaway=takeaway,
        uncertainty=("Confirm CVSS and affected version range in the linked advisory "
                     "before acting.") if is_security else "",
        vendor_framed=False,
    )


def _why(category: str, comp_name: str, gap: str) -> str:
    base = {
        "security": f"A security issue in {comp_name}, which you run. Exposure depends on your version and config.",
        "breaking_change": f"A breaking change or deprecation in {comp_name}; an upgrade will need planning, not a bump.",
        "release": f"A routine update to {comp_name} you run.",
    }.get(category, f"Touches {comp_name}.")
    return (base + " " + gap).strip()


def _takeaway(label: str, comp_name: str) -> str:
    return {
        "patch_now": f"Patch {comp_name} on your next change window or sooner; check the affected range first.",
        "security_review": f"Review whether your {comp_name} config is in the affected path, then schedule a patch.",
        "upgrade_planning": f"Add {comp_name} to upgrade planning; read the migration notes before bumping.",
        "routine_update": f"Low urgency; fold into your normal {comp_name} update cadence.",
        "noise": "Does not touch your stack; ignored.",
    }.get(label, "Review.")
