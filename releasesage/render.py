"""HTML renderer for release-sage.

The page answers one question an on-call engineer has: "is there anything I
need to do?" The signature element is the verdict banner — either an
ACTION NEEDED list ranked by urgency, or an ALL CLEAR stamp. The rejection
ledger shows what was checked and skipped (wrong version, not your stack), so
"all clear" is auditable, not blind.
"""
from __future__ import annotations

import html
import time

from .models import Briefing, Item

_CSS = """
:root{
  --bg:#0F1419; --panel:#171D24; --line:#27313B; --ink:#E6EDF3; --muted:#8B97A3;
  --crit:#E5484D; --warn:#E8A33D; --ok:#3FB950; --info:#4C8DE0;
}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,sans-serif;padding:40px 18px}
.wrap{max-width:820px;margin:0 auto}
.mono{font-family:ui-monospace,"SF Mono",Menlo,monospace}
.kicker{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.2em;
  text-transform:uppercase;color:var(--muted)}
h1{font-size:26px;font-weight:650;letter-spacing:-.01em;margin:4px 0}
.window{color:var(--muted);font-size:13px}
.verdict{margin:24px 0;border-radius:10px;padding:18px 20px;display:flex;
  align-items:center;gap:16px;font-weight:600}
.verdict.clear{background:rgba(63,185,80,.12);border:1px solid var(--ok);color:var(--ok)}
.verdict.action{background:rgba(229,72,77,.10);border:1px solid var(--crit);color:var(--ink)}
.verdict .big{font-family:ui-monospace,monospace;font-size:22px;letter-spacing:.04em}
.item{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:18px 20px;margin-bottom:14px}
.item.patch_now{border-left:4px solid var(--crit)}
.item.security_review{border-left:4px solid var(--warn)}
.item.upgrade_planning{border-left:4px solid var(--info)}
.item.routine_update{border-left:4px solid var(--muted)}
.row1{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px}
.label{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.08em;
  text-transform:uppercase;padding:3px 9px;border-radius:5px;font-weight:700}
.label.patch_now{background:var(--crit);color:#fff}
.label.security_review{background:var(--warn);color:#1b1b1b}
.label.upgrade_planning{background:var(--info);color:#fff}
.label.routine_update{background:var(--line);color:var(--muted)}
.urg{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}
.item h3{font-size:17px;font-weight:600;line-height:1.3}
.item h3 a{color:var(--ink);text-decoration:none;border-bottom:1px solid var(--line)}
.comp{font-family:ui-monospace,monospace;font-size:12px;color:var(--info);margin:6px 0 12px}
.block{margin-top:10px}
.block b{font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.12em;
  text-transform:uppercase;color:var(--muted);display:block;margin-bottom:2px}
.block p{font-size:14px;color:var(--ink)}
h2{font-family:ui-monospace,monospace;font-size:12px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--muted);margin:28px 0 12px;
  border-bottom:1px solid var(--line);padding-bottom:6px}
.ledger .l{display:flex;gap:12px;padding:8px 0;border-bottom:1px dotted var(--line);font-size:13px}
.ledger .l .t{flex:1;color:var(--muted)}
.ledger .l .r{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted);text-align:right}
.tele{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted);
  margin-top:32px;border-top:1px solid var(--line);padding-top:10px}
"""

_URG = {"patch_now": "patch now", "security_review": "review", "upgrade_planning": "plan upgrade",
        "routine_update": "routine"}


def render(b: Briefing) -> str:
    e = html.escape
    admitted = sorted([i for i in b.items if i.admitted], key=lambda i: i.cls.urgency, reverse=True)
    rejected = [i for i in b.items if not i.admitted]

    if b.gate.published:
        n = len(admitted)
        crit = sum(1 for i in admitted if i.cls.signal_label == "patch_now")
        sub = f"{n} change{'s' if n != 1 else ''} affect your stack"
        if crit:
            sub += f" · {crit} need patching now"
        verdict = (f'<div class="verdict action"><span class="big">ACTION NEEDED</span>'
                   f'<span>{sub}</span></div>')
    else:
        verdict = ('<div class="verdict clear"><span class="big">ALL CLEAR</span>'
                   '<span>Nothing in this window needs your attention. '
                   'Sources checked and logged below.</span></div>')

    items_html = "".join(_item(i, e) for i in admitted)
    ledger = "".join(
        f'<div class="l"><div class="t">{e(i.raw.title)}</div>'
        f'<div class="r">{e("; ".join(i.rejection_reasons) or "skipped")}</div></div>'
        for i in rejected) or '<div class="l"><div class="t">Nothing skipped.</div></div>'

    s = b.run_stats
    tele = (f'run: {s.get("succeeded",0)}/{s.get("attempted",0)} feeds ok · '
            f'{s.get("items",0)} items checked · {len(admitted)} actionable · {len(rejected)} skipped')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>release-sage · #{b.number}</title><style>{_CSS}</style></head>
<body><div class="wrap">
<div class="kicker">release-sage · inventory-aware change briefing</div>
<h1>Stack briefing #{b.number}</h1>
<div class="window mono">{e(b.window_start)} → {e(b.window_end)}</div>
{verdict}
{f'<section><h2>Actionable changes</h2>{items_html}</section>' if admitted else ''}
<section class="ledger"><h2>Checked &amp; skipped</h2>{ledger}</section>
<div class="tele">{tele}</div>
</div></body></html>"""


def _item(i: Item, e) -> str:
    c = i.cls
    lbl = c.signal_label
    unc = f'<div class="block"><b>Verify first</b><p>{e(c.uncertainty)}</p></div>' if c.uncertainty else ""
    return f"""<article class="item {lbl}">
<div class="row1"><span class="label {lbl}">{e(_URG.get(lbl, lbl))}</span>
<span class="urg">urgency {c.urgency}/100</span></div>
<h3><a href="{e(i.raw.url)}">{e(i.raw.title)}</a></h3>
<div class="comp">{e(c.category.replace('_',' '))}</div>
<div class="block"><b>Why it matters</b><p>{e(c.why_it_matters)}</p></div>
<div class="block"><b>What to do</b><p>{e(c.builder_takeaway)}</p></div>
{unc}
</article>"""
