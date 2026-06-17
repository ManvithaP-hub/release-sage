"""release-sage web UI.

A small read-only web app over the SQLite database the pipeline already writes.
Three views:

  /            latest briefing (verdict + actionable items + skipped ledger)
  /history     list of past briefings with their verdicts
  /briefing/N  a specific past briefing
  /explore     filter every stored item by component, signal, urgency

It adds no storage and no pipeline — it reads what `releasesage run` produced.
Server-rendered HTML (no build step, no JS framework) in the same instrument
style as the static briefing pages. Run:

    pip install fastapi uvicorn
    python -m releasesage.web --db out/releasesage.db
    # then open http://127.0.0.1:8000

Read-only by design: it never writes to the database.
"""
from __future__ import annotations

import html
import json
import os
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

DB_PATH = os.environ.get("RELEASESAGE_DB", "out/releasesage.db")

app = FastAPI(title="release-sage")


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


# --------------------------------------------------------------------------
# shared chrome
# --------------------------------------------------------------------------

_CSS = """
:root{--bg:#0F1419;--panel:#171D24;--line:#27313B;--ink:#E6EDF3;--muted:#8B97A3;
--crit:#E5484D;--warn:#E8A33D;--ok:#3FB950;--info:#4C8DE0;}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,sans-serif}
a{color:var(--info);text-decoration:none}
nav{position:sticky;top:0;background:#0F1419ee;border-bottom:1px solid var(--line);
padding:14px 24px;display:flex;gap:20px;align-items:center;backdrop-filter:blur(6px)}
nav .brand{font-weight:700;letter-spacing:-.01em;color:var(--ink)}
nav .brand b{color:var(--ok)}
nav a{font-family:ui-monospace,monospace;font-size:13px;color:var(--muted)}
nav a:hover{color:var(--ink)}
.wrap{max-width:880px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:24px;font-weight:650;margin-bottom:4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.verdict{border-radius:10px;padding:16px 18px;margin:18px 0;font-weight:600;display:flex;gap:14px;align-items:center}
.verdict.clear{background:rgba(63,185,80,.12);border:1px solid var(--ok);color:var(--ok)}
.verdict.action{background:rgba(229,72,77,.10);border:1px solid var(--crit);color:var(--ink)}
.verdict .big{font-family:ui-monospace,monospace;font-size:20px;letter-spacing:.04em}
.item{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:12px}
.item.patch_now{border-left:4px solid var(--crit)}
.item.security_review{border-left:4px solid var(--warn)}
.item.upgrade_planning{border-left:4px solid var(--info)}
.item.routine_update,.item.noise{border-left:4px solid var(--muted)}
.row1{display:flex;justify-content:space-between;gap:10px;margin-bottom:6px}
.label{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.06em;text-transform:uppercase;
padding:2px 8px;border-radius:5px;font-weight:700}
.label.patch_now{background:var(--crit);color:#fff}
.label.security_review{background:var(--warn);color:#1b1b1b}
.label.upgrade_planning{background:var(--info);color:#fff}
.label.routine_update,.label.noise{background:var(--line);color:var(--muted)}
.urg{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}
.item h3{font-size:16px;font-weight:600}
.item p{font-size:14px;color:var(--ink);margin-top:6px}
.item .verify{font-size:13px;color:var(--muted);margin-top:8px;font-style:italic}
.brow{display:block;background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:12px 16px;margin-bottom:8px;color:var(--ink)}
.brow:hover{border-color:var(--info)}
.brow .meta{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}
.pill{display:inline-block;font-family:ui-monospace,monospace;font-size:11px;padding:1px 7px;border-radius:4px;border:1px solid var(--line);color:var(--muted)}
.pill.pub{border-color:var(--crit);color:var(--crit)}
.pill.clear{border-color:var(--ok);color:var(--ok)}
form.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
form.filters select,form.filters input{background:var(--panel);color:var(--ink);
border:1px solid var(--line);border-radius:6px;padding:6px 10px;font-family:ui-monospace,monospace;font-size:13px}
form.filters button{background:var(--info);color:#fff;border:0;border-radius:6px;padding:6px 14px;cursor:pointer}
.empty{color:var(--muted);padding:30px 0;text-align:center}
"""


def _page(title: str, body: str) -> str:
    e = html.escape
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>{_CSS}</style></head><body>
<nav><span class="brand">release<b>-sage</b></span>
<a href="/">Latest</a><a href="/history">History</a><a href="/explore">Explore</a></nav>
<div class="wrap">{body}</div></body></html>"""


def _item_card(r: sqlite3.Row, e) -> str:
    lbl = r["cls_signal_label"]
    verify = f'<div class="verify">{e(r["cls_uncertainty"])}</div>' if r["cls_uncertainty"] else ""
    return f"""<div class="item {lbl}">
<div class="row1"><span class="label {lbl}">{e(lbl.replace('_',' '))}</span>
<span class="urg">urgency {r['cls_urgency']}/100 · {e(r['cls_category'].replace('_',' '))}</span></div>
<h3><a href="{e(r['url'])}">{e(r['title'])}</a></h3>
<p>{e(r['cls_why_it_matters'])}</p>
<p><b>What to do:</b> {e(r['cls_builder_takeaway'])}</p>{verify}</div>"""


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def latest():
    e = html.escape
    try:
        c = _conn()
    except Exception:
        return _page("release-sage", '<div class="empty">No database found. Run `releasesage run` first.</div>')
    b = c.execute("SELECT * FROM briefings ORDER BY number DESC LIMIT 1").fetchone()
    if not b:
        return _page("release-sage", '<div class="empty">No briefings yet. Run `releasesage run`.</div>')
    return _page("release-sage · latest", _briefing_body(c, b, e))


@app.get("/briefing/{number}", response_class=HTMLResponse)
def briefing(number: int):
    e = html.escape
    c = _conn()
    b = c.execute("SELECT * FROM briefings WHERE number=?", (number,)).fetchone()
    if not b:
        return _page("release-sage", '<div class="empty">No such briefing.</div>')
    return _page(f"release-sage · #{number}", _briefing_body(c, b, e))


def _briefing_body(c, b, e) -> str:
    items = c.execute("SELECT * FROM items WHERE briefing_number=? ORDER BY cls_urgency DESC",
                      (b["number"],)).fetchall()
    admitted = [i for i in items if i["admitted"]]
    rejected = [i for i in items if not i["admitted"]]
    if b["published"]:
        crit = sum(1 for i in admitted if i["cls_signal_label"] == "patch_now")
        sub = f"{len(admitted)} change(s) affect your stack" + (f" · {crit} need patching now" if crit else "")
        verdict = f'<div class="verdict action"><span class="big">ACTION NEEDED</span><span>{e(sub)}</span></div>'
    else:
        verdict = ('<div class="verdict clear"><span class="big">ALL CLEAR</span>'
                   '<span>Nothing in this window needs your attention.</span></div>')
    cards = "".join(_item_card(i, e) for i in admitted) or '<div class="empty">No actionable items.</div>'
    ledger = "".join(
        f'<div class="brow"><span>{e(i["title"])}</span> '
        f'<span class="meta">— {e(json.loads(i["rejection_reasons"] or "[]") and "; ".join(json.loads(i["rejection_reasons"])) or "skipped")}</span></div>'
        for i in rejected) or '<div class="empty">Nothing skipped.</div>'
    return f"""<h1>Briefing #{b['number']}</h1>
<div class="sub">{e(b['window_start'])} → {e(b['window_end'])}</div>
{verdict}
<h3 style="font-family:ui-monospace,monospace;font-size:13px;color:var(--muted);margin:24px 0 12px">ACTIONABLE</h3>
{cards}
<h3 style="font-family:ui-monospace,monospace;font-size:13px;color:var(--muted);margin:24px 0 12px">CHECKED &amp; SKIPPED</h3>
{ledger}"""


@app.get("/history", response_class=HTMLResponse)
def history():
    e = html.escape
    try:
        c = _conn()
    except Exception:
        return _page("release-sage", '<div class="empty">No database found.</div>')
    rows = c.execute("SELECT * FROM briefings ORDER BY number DESC LIMIT 100").fetchall()
    if not rows:
        return _page("release-sage · history", '<div class="empty">No briefings yet.</div>')
    body = "<h1>Briefing history</h1><div class='sub'>Every run, newest first.</div>"
    for b in rows:
        pill = '<span class="pill pub">ACTION</span>' if b["published"] else '<span class="pill clear">ALL CLEAR</span>'
        body += (f'<a class="brow" href="/briefing/{b["number"]}">'
                 f'<b>Briefing #{b["number"]}</b> {pill} '
                 f'<span class="meta">· {e(b["window_end"])} · '
                 f'{b["admitted"]} actionable · {b["rejected"]} skipped</span></a>')
    return _page("release-sage · history", body)


@app.get("/explore", response_class=HTMLResponse)
def explore(component: str = Query("all"), signal: str = Query("all"),
            min_urgency: int = Query(0)):
    e = html.escape
    try:
        c = _conn()
    except Exception:
        return _page("release-sage", '<div class="empty">No database found.</div>')
    comps = [r["source_id"].split("-")[0] for r in
             c.execute("SELECT DISTINCT source_id FROM items").fetchall()]
    comps = sorted(set(comps))
    signals = [r["cls_signal_label"] for r in
               c.execute("SELECT DISTINCT cls_signal_label FROM items").fetchall()]

    q = "SELECT * FROM items WHERE cls_urgency >= ?"
    args: list = [min_urgency]
    if signal != "all":
        q += " AND cls_signal_label=?"; args.append(signal)
    if component != "all":
        q += " AND source_id LIKE ?"; args.append(f"{component}%")
    q += " ORDER BY cls_urgency DESC, briefing_number DESC LIMIT 200"
    rows = c.execute(q, args).fetchall()

    def opts(values, current):
        out = '<option value="all">all</option>'
        for v in values:
            sel = " selected" if v == current else ""
            out += f'<option value="{e(v)}"{sel}>{e(v.replace("_"," "))}</option>'
        return out

    form = f"""<form class="filters" method="get">
<select name="component">{opts(comps, component)}</select>
<select name="signal">{opts(signals, signal)}</select>
<input name="min_urgency" type="number" min="0" max="100" value="{min_urgency}" placeholder="min urgency">
<button type="submit">Filter</button></form>"""
    cards = "".join(_item_card(r, e) for r in rows) or '<div class="empty">No items match.</div>'
    return _page("release-sage · explore",
                 f"<h1>Explore</h1><div class='sub'>Filter every stored item.</div>{form}{cards}")


def main():
    import argparse
    import uvicorn
    global DB_PATH
    p = argparse.ArgumentParser(prog="releasesage.web")
    p.add_argument("--db", default=DB_PATH)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    os.environ["RELEASESAGE_DB"] = args.db
    DB_PATH = args.db
    print(f"release-sage web UI on http://{args.host}:{args.port}  (db: {args.db})")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
