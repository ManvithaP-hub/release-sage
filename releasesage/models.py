"""brief-sage core data models."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Source:
    id: str
    name: str
    url: str
    kind: str = "rss"           # rss | html | github_releases | github_security | k8s_changelog | arxiv
    tier: str = "secondary"     # primary | secondary | tertiary
    category: str = "business"
    feed: Optional[str] = None
    component: Optional[str] = None   # inventory component id this source watches


@dataclass
class RawItem:
    source_id: str
    title: str
    url: str
    summary: str = ""
    published: Optional[str] = None   # ISO timestamp if known

    @property
    def uid(self) -> str:
        return hashlib.sha256(f"{self.source_id}|{self.url}|{self.title}".encode()).hexdigest()[:16]


@dataclass
class Classification:
    category: str
    signal_label: str
    audiences: list[str]
    substance: int        # 0-100
    novelty: int          # 0-100 (filled by threading step)
    hype_risk: int        # 0-100
    urgency: int          # 0-100
    what_happened: str
    why_it_matters: str
    builder_takeaway: str
    uncertainty: str = ""
    vendor_framed: bool = False

    @property
    def overall(self) -> int:
        return round(0.45 * self.substance + 0.25 * self.novelty
                     + 0.15 * self.urgency + 0.15 * (100 - self.hype_risk))


@dataclass
class Item:
    raw: RawItem
    source: Source
    cls: Classification
    thread_id: Optional[str] = None
    thread_position: int = 1          # 1 = new story, >1 = follow-up
    corroboration: str = "unconfirmed"  # primary | corroborated | unconfirmed
    admitted: bool = False
    rejection_reasons: list[str] = field(default_factory=list)

    def to_record(self) -> dict:
        d = {
            "uid": self.raw.uid,
            "source_id": self.raw.source_id,
            "title": self.raw.title,
            "url": self.raw.url,
            "summary": self.raw.summary,
            "published": self.raw.published,
            "tier": self.source.tier,
            "thread_id": self.thread_id,
            "thread_position": self.thread_position,
            "corroboration": self.corroboration,
            "admitted": int(self.admitted),
            "rejection_reasons": json.dumps(self.rejection_reasons),
        }
        d.update({f"cls_{k}": v for k, v in asdict(self.cls).items()
                  if not isinstance(v, list)})
        d["cls_audiences"] = json.dumps(self.cls.audiences)
        d["cls_overall"] = self.cls.overall
        return d


@dataclass
class Angle:
    item_uid: str
    hook: str
    body: str
    formats: list[str]
    audiences: list[str]


@dataclass
class GateDecision:
    published: bool
    reasons: list[str]
    admitted: int
    rejected: int
    total_information: int


@dataclass
class Briefing:
    number: int
    window_start: str
    window_end: str
    items: list[Item]
    angles: list[Angle]
    gate: GateDecision
    run_stats: dict = field(default_factory=dict)
    generated_at: float = field(default_factory=time.time)
