"""Threading, novelty, corroboration, and the quality gate.

These three small modules are the entire difference between this pipeline and
the reference app:

  threading     — clusters items into story threads and scores NOVELTY against
                  history, so re-announcements stop counting as news.
  corroborate   — makes verification mechanical: a secondary/tertiary claim is
                  'corroborated' only when a primary item lands in its thread.
  quality gate  — admits items, then decides whether the briefing as a whole
                  deserves to exist. "Nothing important happened" is a valid,
                  publishable verdict; templated filler is not.
"""
from __future__ import annotations

import re

from .models import GateDecision, Item

_STOP = set("the a an of for to in on with and or is are was were be as at by "
            "from this that its it's how what why new latest update".split())


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in _STOP and len(w) > 2}


def similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# --------------------------------------------------------------------------
# Threading + novelty
# --------------------------------------------------------------------------

def thread_and_score_novelty(items: list[Item], history: list[dict], policy: dict) -> None:
    """Assign thread ids and novelty scores in place.

    history: prior item records [{uid, title, summary, thread_id}, ...]
    Similarity is the max of title-vs-title and fulltext-vs-fulltext, so the
    same story with different summaries still clusters.
    """
    threshold = policy["threading"]["similarity_threshold"]
    threads: dict[str, list[tuple[str, str]]] = {}
    for rec in history:
        threads.setdefault(rec.get("thread_id") or rec["uid"], []).append(
            (rec["title"], f"{rec['title']} {rec.get('summary', '')}"))

    for item in items:
        title = item.raw.title
        full = f"{item.raw.title} {item.raw.summary}"
        best_id, best_sim = None, 0.0
        for tid, entries in threads.items():
            sim = max(max(similarity(title, t), similarity(full, f))
                      for t, f in entries)
            if sim > best_sim:
                best_id, best_sim = tid, sim
        if best_id and best_sim >= threshold:
            item.thread_id = best_id
            item.thread_position = len(threads[best_id]) + 1
            # Follow-up coverage: novelty is what's NOT already in the thread
            item.cls.novelty = max(5, int(round((1 - best_sim) * 100)))
        else:
            item.thread_id = item.raw.uid
            item.thread_position = 1
            item.cls.novelty = 85
        threads.setdefault(item.thread_id, []).append((title, full))


# --------------------------------------------------------------------------
# Corroboration
# --------------------------------------------------------------------------

def corroborate(items: list[Item], history: list[dict]) -> None:
    primary_threads = {rec.get("thread_id") for rec in history if rec.get("tier") == "primary"}
    primary_threads |= {i.thread_id for i in items if i.source.tier == "primary"}
    for item in items:
        if item.source.tier == "primary":
            item.corroboration = "primary"
        elif item.thread_id in primary_threads:
            item.corroboration = "corroborated"
        else:
            item.corroboration = "unconfirmed"


# --------------------------------------------------------------------------
# Quality gate
# --------------------------------------------------------------------------

_SIGNAL_RANK = ["noise", "routine_update", "upgrade_planning",
                "security_review", "patch_now"]


def apply_gate(items: list[Item], policy: dict) -> GateDecision:
    g = policy["quality_gate"]
    cap = g.get("uncorroborated_max_signal", "watch")

    for item in items:
        reasons = []
        if item.cls.signal_label in g["drop_signal_labels"]:
            reasons.append(f"signal_label={item.cls.signal_label}")
        if item.cls.substance < g["min_substance"]:
            reasons.append(f"substance {item.cls.substance} < {g['min_substance']}")
        if item.cls.novelty < g["min_novelty"]:
            reasons.append(f"novelty {item.cls.novelty} < {g['min_novelty']} (re-announcement)")
        # cap uncorroborated secondary claims — they can pass, but never as top signal
        if item.corroboration == "unconfirmed" and item.source.tier != "primary":
            if _SIGNAL_RANK.index(item.cls.signal_label) > _SIGNAL_RANK.index(cap):
                item.cls.signal_label = cap
        item.rejection_reasons = reasons
        item.admitted = not reasons

    admitted = [i for i in items if i.admitted]
    total_info = sum(i.cls.substance for i in admitted)
    top = max((i.cls.substance for i in admitted), default=0)

    reasons = []
    if len(admitted) < g["min_items"]:
        reasons.append(f"admitted items {len(admitted)} < min_items {g['min_items']}")
    if top < g["min_top_substance"]:
        reasons.append(f"top substance {top} < {g['min_top_substance']}")
    if total_info < g["min_total_information"]:
        reasons.append(f"total information {total_info} < {g['min_total_information']}")

    return GateDecision(published=not reasons, reasons=reasons,
                        admitted=len(admitted), rejected=len(items) - len(admitted),
                        total_information=total_info)
