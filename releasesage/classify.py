"""Item classification.

Two modes:
  LLM mode       — Anthropic API with a JSON schema and rubric anchors from
                   config/policy.yaml. Cheap model for the broad pass; the
                   pipeline only spends a stronger model on items that survive
                   the quality gate (see pipeline.py).
  Heuristic mode — deterministic, dependency-free scoring so the pipeline runs
                   end-to-end without a key (CI, demos). Not a substitute for
                   the LLM pass; it exists so the *system* is always testable.

Set ANTHROPIC_API_KEY to enable LLM mode. BRIEFSAGE_MODEL overrides the model.
"""
from __future__ import annotations

import json
import os
import re

from .models import Classification, RawItem, Source

CLASSIFY_MODEL = os.environ.get("BRIEFSAGE_MODEL", "claude-haiku-4-5-20251001")
ENRICH_MODEL = os.environ.get("BRIEFSAGE_ENRICH_MODEL", "claude-sonnet-4-6")

SCHEMA_KEYS = ["category", "signal_label", "audiences", "substance", "hype_risk",
               "urgency", "what_happened", "why_it_matters", "builder_takeaway",
               "uncertainty", "vendor_framed"]


def llm_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def classify(raw: RawItem, source: Source, policy: dict) -> Classification:
    if llm_available():
        try:
            return _classify_llm(raw, source, policy)
        except Exception:
            pass  # fall through to heuristic rather than fail the run
    return _classify_heuristic(raw, source, policy)


# --------------------------------------------------------------------------
# LLM mode
# --------------------------------------------------------------------------

def _classify_llm(raw: RawItem, source: Source, policy: dict) -> Classification:
    import anthropic
    client = anthropic.Anthropic()
    rubric = json.dumps(policy["scoring"], indent=2)
    labels = policy["signal_labels"]
    cats = policy["categories"]
    auds = policy["audiences"]

    prompt = f"""You are the classification layer of an AI-news pipeline. Score strictly
against the rubric anchors; do not inflate. Vendor self-claims are vendor_framed=true.

RUBRIC ANCHORS:
{rubric}

SOURCE: {source.name} (tier={source.tier}, kind={source.kind})
TITLE: {raw.title}
SUMMARY: {raw.summary[:1500]}

Respond with ONLY a JSON object, no markdown fences, with keys:
category (one of {cats}),
signal_label (one of {labels}),
audiences (subset of {auds}),
substance (0-100), hype_risk (0-100), urgency (0-100),
what_happened (2 factual sentences),
why_it_matters (2 sentences of consequence, not restatement),
builder_takeaway (1 imperative sentence: test / ignore / watch, and why),
uncertainty (1 sentence on what is unconfirmed, or empty string),
vendor_framed (boolean)."""

    msg = client.messages.create(model=CLASSIFY_MODEL, max_tokens=800,
                                 messages=[{"role": "user", "content": prompt}])
    text = "".join(b.text for b in msg.content if b.type == "text")
    data = json.loads(re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M))
    data = {k: data.get(k) for k in SCHEMA_KEYS}
    data["novelty"] = 50  # threading step overwrites
    return Classification(**data)


# --------------------------------------------------------------------------
# Heuristic mode (offline)
# --------------------------------------------------------------------------

_CAT_HINTS = {
    "models": ["model", "weights", "benchmark", "llm", "gpt", "claude", "gemini", "llama"],
    "developer_tools": ["sdk", "api", "changelog", "cli", "ide", "release notes"],
    "open_source": ["open source", "github", "release", "apache", "mit license", "vllm", "langchain"],
    "infrastructure": ["gpu", "datacenter", "data center", "chip", "inference", "cluster",
                       "kubernetes", "keda", "argo", "gigawatt"],
    "agents": ["agent", "agentic", "orchestrat", "tool use", "mcp"],
    "research": ["paper", "arxiv", "preprint", "study"],
    "policy": ["regulation", "policy", "nist", "eu ai act", "compliance", "executive order"],
    "business": ["funding", "acquisition", "revenue", "valuation", "partnership", "equity", "ipo"],
}

_THIN_MARKERS = ["how to watch", "what to expect", "roundup", "everything you need",
                 "top 10", "preview of", "rumor", "reportedly", "teaser"]
_CONCRETE_MARKERS = ["available", "launched", "released", "ships", "pricing", "ga ",
                     "general availability", "version", "v1", "v2", "benchmark",
                     "filed", "published", "preview", "rollout"]


def _classify_heuristic(raw: RawItem, source: Source, policy: dict) -> Classification:
    text = f"{raw.title} {raw.summary}".lower()

    # category: word-boundary hint matching, with the source's declared
    # category as a prior (an arXiv feed really is research; trust the registry)
    scores = {cat: 0 for cat in _CAT_HINTS}
    scores[source.category] = scores.get(source.category, 0) + 2
    for cat, hints in _CAT_HINTS.items():
        for h in hints:
            if re.search(rf"\b{re.escape(h)}", text):
                scores[cat] += 1
    category = max(scores, key=scores.get)

    # substance
    substance = 35
    substance += 12 * min(3, sum(1 for m in _CONCRETE_MARKERS if m in text))
    substance -= 18 * min(2, sum(1 for m in _THIN_MARKERS if m in text))
    if len(raw.summary) > 400:
        substance += 8
    if re.search(r"\d", raw.title + raw.summary):
        substance += 6
    if source.tier == "primary":
        substance += 10
    elif source.tier == "tertiary":
        substance -= 8
    substance = max(5, min(95, substance))

    vendor_framed = source.tier == "primary" and source.kind in ("rss", "html") \
        and category in ("models", "developer_tools", "business")
    hype_risk = 55 if vendor_framed else (30 if source.tier == "primary" else 45)
    if any(m in text for m in _THIN_MARKERS):
        hype_risk += 15
    hype_risk = min(90, hype_risk)

    urgency = 60 if "available" in text or "launched" in text else 40

    if substance < 30:
        label = "noise"
    elif category == "research":
        label = "research_signal"
    elif category in ("business",):
        label = "business_signal"
    elif category == "policy":
        label = "policy_signal"
    elif substance >= 70 and source.tier == "primary":
        label = "high_signal"
    elif substance >= 55:
        label = "builder_useful"
    else:
        label = "watch"

    audiences = {"models": ["ai_engineers"], "developer_tools": ["ai_engineers", "software_engineers"],
                 "open_source": ["ai_engineers", "software_engineers"],
                 "infrastructure": ["platform_sre", "ai_engineers"],
                 "agents": ["ai_engineers", "founders"], "research": ["ai_engineers", "students"],
                 "business": ["founders", "gtm", "enterprise"], "policy": ["enterprise", "founders"],
                 "community": ["ai_engineers"]}.get(category, ["ai_engineers"])

    first = raw.summary.split(". ")[0][:280] if raw.summary else raw.title
    return Classification(
        category=category, signal_label=label, audiences=audiences,
        substance=substance, novelty=50, hype_risk=hype_risk, urgency=urgency,
        what_happened=f"{source.name}: {raw.title}. {first}".strip(),
        why_it_matters=_why(category, source),
        builder_takeaway=_takeaway(label),
        uncertainty="Vendor-framed; treat self-reported claims as unverified."
        if vendor_framed else "",
        vendor_framed=vendor_framed,
    )


def _why(category: str, source: Source) -> str:
    table = {
        "models": "Capability shifts change what is worth building versus waiting for.",
        "developer_tools": "API surface changes land directly in builder workflows and costs.",
        "open_source": "Upstream releases set what self-hosted stacks can do this quarter.",
        "infrastructure": "Compute economics constrain every deployment decision downstream.",
        "agents": "Agentic patterns are where orchestration design choices get validated.",
        "research": "Methods here typically reach production toolchains within months.",
        "business": "Capital and pricing moves reveal where platforms expect control to sit.",
        "policy": "Compliance posture changes are binding in a way product launches are not.",
        "community": "Practitioner consensus often front-runs official documentation.",
    }
    base = table.get(category, "Relevant to builders tracking this category.")
    if source.tier != "primary":
        base += " Secondary commentary; weight accordingly."
    return base


def _takeaway(label: str) -> str:
    return {
        "high_signal": "Test against your core use case this week.",
        "builder_useful": "Skim the primary source; adopt if it touches your stack.",
        "research_signal": "Read the abstract; flag for your next architecture review.",
        "business_signal": "Use as market context, not a roadmap.",
        "policy_signal": "Check applicability with whoever owns your compliance posture.",
        "watch": "Watch for primary-source confirmation before acting.",
        "noise": "Ignore.",
    }.get(label, "Watch.")
