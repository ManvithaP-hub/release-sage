# release-sage

[![tests](https://github.com/ManvithaP-hub/release-sage/actions/workflows/ci.yml/badge.svg)](https://github.com/ManvithaP-hub/release-sage/actions/workflows/ci.yml)


An **inventory-aware change briefing** for your infrastructure. You declare what
you actually run (KEDA, Argo CD, External Secrets, Kyverno, EKS version); every
run it checks the release and security-advisory feeds for *those components only*
and gives you one of two answers:

- **ALL CLEAR** — nothing in this window needs your attention (logged, auditable).
- **ACTION NEEDED** — these N changes touch your stack, ranked by urgency, each
  with what to do.

The point is the filter. Generic release radars (Dependabot, Renovate, "what's
new" feeds) tell you *everything changed*. release-sage tells you *what changed
that affects what you run, and whether you need to act tonight* — and stays
silent when nothing does.

## Why it's different

The novel layer is `inventory.py`: an item only clears the gate if it touches a
component in your `config/inventory.yaml`, and **urgency is scored against the
version you're on**, not in the abstract. A release you're already running, or a
project you don't run, scores zero and never reaches you. Security advisories and
breaking-change/deprecation notices are weighted equally — the two things that
actually wake up a platform engineer.

For security items it goes further: instead of guessing severity from
keywords, it queries **OSV (osv.dev)** for the authoritative CVSS score and
*affected version ranges*, then checks the version you actually run against
them. The result is a precise verdict — **confirmed affected** (with the CVE,
CVSS, and fixed version) or **not affected, you're already safe** — so you
don't get "review this CVE" busywork for a version that was never vulnerable.
OSV lookups degrade gracefully to the heuristic if the service is unreachable.

It's built on a quality-gated pipeline (the "ALL CLEAR" verdict is the gate
refusing to publish noise) with source-tiering, story threading, and
corroboration carried over from a general briefing engine.

## Configure

`config/inventory.yaml` — what you run. This is the whole point; edit it:

```yaml
components:
  - id: keda
    name: KEDA
    repo: kedacore/keda
    version: "2.14.0"        # what you're on; newer releases get flagged
platforms:
  - id: eks
    name: Amazon EKS
    version: "1.30"
```

`config/sources.yaml` — release + GHSA security feeds per component.
`config/policy.yaml` — gate thresholds and urgency rubric.


## Auto-discover your inventory (no hand-editing)

Instead of editing `inventory.yaml` by hand, point release-sage at a cluster and
let it build the inventory from what's actually running:

```bash
# uses your current kubeconfig context, read-only:
python -m releasesage discover --out config/inventory.yaml

# or a specific context / kubeconfig:
python -m releasesage discover --context my-eks-cluster
```

It inspects the cluster in three read-only passes and writes a ready-to-use
inventory:

1. **Helm releases** — decodes Helm's release secrets for chart + app version
   (the most reliable version signal).
2. **Workload images** — Deployments/StatefulSets/DaemonSets, to catch
   components installed without Helm.
3. **CRD groups** — detects operators (KEDA, Argo CD, Kyverno, ESO, …) by their
   API groups even when workloads are named generically; flags them
   `version: UNKNOWN` for you to confirm.

Each entry records *how* it was discovered (`discovered_via`). Review anything
marked `UNKNOWN` or `REVIEW` before relying on the briefing. The set of
recognizable components lives in `releasesage/discover.py::CATALOG` — extend it
to teach discovery about more tools.

This is the kubeconfig version (immediately runnable). An in-cluster operator
that maintains the inventory continuously is the next increment.

## Run

```bash
pip install -r requirements.txt

# offline demos:
python -m releasesage run --fixtures fixtures/window_quiet.json    # → ALL CLEAR
python -m releasesage run --fixtures fixtures/window_action.json   # → ACTION NEEDED

# live (fetches GitHub release/advisory feeds for your inventory):
python -m releasesage run

# point at your own inventory:
python -m releasesage run --inventory ~/my-cluster-inventory.yaml
```

Output: `out/briefing_NNN.html` + `out/releasesage.db`. Tests: `python -m pytest tests/ -q`.

## Deploy (EKS)

`k8s/cronjob.yaml` runs it every 2 hours; `Dockerfile` builds the image. A KEDA
ScaledJob with a cron scaler is a drop-in if you want on-demand triggers too.

## Honest limitations

- Heuristic classification only so far (the LLM path from the engine is present
  but not wired into the ops classifier; the deterministic signals — CVSS
  strings, semver, breaking-change markers — are actually reliable for ops data).
- `version_gap` uses simple semver; pre-release/build tags aren't fully handled.
- The AWS EKS "what's new" source is an HTML stub; add proper extraction.
- No web UI yet; output is static HTML. The db schema supports building one.
- Inventory matching is name/repo based. A component whose release notes never
  name themselves would be missed (rare for GitHub release feeds).
