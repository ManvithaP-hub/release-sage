"""Pipeline orchestration + CLI.

  python -m releasesage run --fixtures fixtures/window_thin.json     # offline demo
  python -m releasesage run                                          # live fetch
  ANTHROPIC_API_KEY=... python -m releasesage run                    # LLM classification

Stages: collect → classify → thread/novelty → corroborate → gate → angles
→ persist → render. The gate can veto the whole briefing; that verdict is
itself published and logged.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import yaml

from . import adapters, classify, gate, inventory as inv, render, store
from .models import Briefing, Item

ROOT = Path(__file__).resolve().parent.parent


def run(fixture_path: str | None, db_path: str, out_dir: str,
        sources_path: str, policy_path: str, inventory_path: str | None = None) -> Briefing:
    policy = yaml.safe_load(Path(policy_path).read_text())
    sources = adapters.load_sources(sources_path)
    inv_path = inventory_path or str(ROOT / "config" / "inventory.yaml")
    inventory = inv.load_inventory(inv_path)
    conn = store.connect(db_path)

    window_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    window_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))

    collected, telemetry = adapters.collect(sources, fixture_path)
    mode = "llm" if classify.llm_available() else "heuristic"
    print(f"[collect] {telemetry['succeeded']}/{telemetry['attempted']} sources ok, "
          f"{telemetry['items']} items · classifier={mode}", file=sys.stderr)

    items = [Item(raw=raw, source=src, cls=inv.classify_release(raw, src, inventory, policy))
             for src, raw in collected]

    history = store.recent_item_history(conn, policy["threading"]["history_days"])
    gate.thread_and_score_novelty(items, history, policy)
    gate.corroborate(items, history)
    decision = gate.apply_gate(items, policy)

    briefing_angles = []  # ops tool: no social angles

    briefing = Briefing(
        number=store.next_briefing_number(conn),
        window_start=window_start, window_end=window_end,
        items=items, angles=briefing_angles, gate=decision, run_stats=telemetry)

    store.save_briefing(conn, briefing)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / f"briefing_{briefing.number:03d}.html"
    html_path.write_text(render.render(briefing))

    verdict = "PUBLISHED" if decision.published else "SUPPRESSED"
    print(f"[gate] {verdict} · admitted={decision.admitted} rejected={decision.rejected} "
          f"info={decision.total_information}"
          + (f" · reasons: {'; '.join(decision.reasons)}" if decision.reasons else ""),
          file=sys.stderr)
    print(f"[out] {html_path}", file=sys.stderr)
    return briefing


def main() -> None:
    p = argparse.ArgumentParser(prog="releasesage")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one briefing window")
    r.add_argument("--fixtures", default=None, help="fixture JSON instead of live fetch")
    r.add_argument("--db", default=str(ROOT / "out" / "releasesage.db"))
    r.add_argument("--out", default=str(ROOT / "out"))
    r.add_argument("--sources", default=str(ROOT / "config" / "sources.yaml"))
    r.add_argument("--policy", default=str(ROOT / "config" / "policy.yaml"))
    r.add_argument("--inventory", default=str(ROOT / "config" / "inventory.yaml"))

    d = sub.add_parser("discover", help="auto-generate inventory from a live cluster")
    d.add_argument("--kubeconfig", default=None, help="path to kubeconfig")
    d.add_argument("--context", default=None, help="kube context to use")
    d.add_argument("--out", default=str(ROOT / "config" / "inventory.yaml"))

    args = p.parse_args()
    if args.cmd == "run":
        run(args.fixtures, args.db, args.out, args.sources, args.policy, args.inventory)
    elif args.cmd == "discover":
        from pathlib import Path as _P
        from . import discover as disc
        try:
            findings = disc.discover(args.kubeconfig, args.context)
        except Exception as exc:  # noqa: BLE001
            print(f"[discover] could not connect to a cluster: {exc}\n"
                  f"          check your kubeconfig/context, or run inside a cluster.",
                  file=sys.stderr)
            sys.exit(1)
        if not findings:
            print("[discover] connected, but found no known components.", file=sys.stderr)
        for f in findings:
            print(f"  found {f.name:28} {f.version:10} ({f.evidence})", file=sys.stderr)
        _P(args.out).write_text(disc.to_inventory_yaml(findings))
        print(f"[discover] wrote {len(findings)} components -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
