"""Automatic cluster inventory discovery.

Replaces hand-editing config/inventory.yaml. Connects to a cluster (via your
kubeconfig, read-only) and builds the inventory from what is ACTUALLY running,
using three passes that catch different installation styles:

  1. Helm releases   — richest source. Helm stores each release as a Secret of
                       type 'helm.sh/release.v1'; the payload carries chart
                       name, chart version, and app version. This is the most
                       reliable version signal.
  2. Workloads       — Deployments/StatefulSets/DaemonSets. Image tags catch
                       components installed without Helm (raw manifests,
                       kustomize, operators' own deployments).
  3. CRDs            — Custom Resource Definitions reveal operators by their
                       API groups (e.g. keda.sh, argoproj.io) even when the
                       workload is named generically.

Findings are matched against a component catalog (which GitHub repo / which
CRD group / which image substring identifies each known tool), then written
as a ready-to-use inventory.yaml.

Everything here is READ-ONLY: list/get on namespaced and cluster resources.
No writes, no agent required. The in-cluster operator is a later increment;
this kubeconfig version is immediately runnable and proves the concept.

Usage:
    python -m releasesage discover --kubeconfig ~/.kube/config --out config/inventory.yaml
    python -m releasesage discover --context my-eks-cluster
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import sys
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Component catalog: how to RECOGNIZE each known tool in a cluster.
# This is the bridge between "what's running" and "what release-sage watches".
# Extend this to teach discovery about more components.
# --------------------------------------------------------------------------

@dataclass
class CatalogEntry:
    id: str
    name: str
    repo: str                       # github repo for release/advisory feeds
    purpose: str
    helm_charts: list[str] = field(default_factory=list)   # chart names
    crd_groups: list[str] = field(default_factory=list)    # CRD api groups
    image_match: list[str] = field(default_factory=list)   # image substrings


CATALOG: list[CatalogEntry] = [
    CatalogEntry("keda", "KEDA", "kedacore/keda", "event-driven autoscaling",
                 helm_charts=["keda"], crd_groups=["keda.sh"],
                 image_match=["kedacore/keda"]),
    CatalogEntry("argocd", "Argo CD", "argoproj/argo-cd", "gitops delivery",
                 helm_charts=["argo-cd", "argocd"], crd_groups=["argoproj.io"],
                 image_match=["argoproj/argocd", "quay.io/argoproj/argocd"]),
    CatalogEntry("external-secrets", "External Secrets Operator",
                 "external-secrets/external-secrets", "secret sync",
                 helm_charts=["external-secrets"],
                 crd_groups=["external-secrets.io"],
                 image_match=["external-secrets/external-secrets"]),
    CatalogEntry("kyverno", "Kyverno", "kyverno/kyverno", "policy enforcement",
                 helm_charts=["kyverno"], crd_groups=["kyverno.io"],
                 image_match=["kyverno/kyverno"]),
    CatalogEntry("cert-manager", "cert-manager", "cert-manager/cert-manager",
                 "certificate management", helm_charts=["cert-manager"],
                 crd_groups=["cert-manager.io"], image_match=["jetstack/cert-manager"]),
    CatalogEntry("istio", "Istio", "istio/istio", "service mesh",
                 helm_charts=["istiod", "istio-base"], crd_groups=["istio.io"],
                 image_match=["istio/pilot", "istio/proxyv2"]),
    CatalogEntry("prometheus", "Prometheus", "prometheus/prometheus", "monitoring",
                 helm_charts=["kube-prometheus-stack", "prometheus"],
                 crd_groups=["monitoring.coreos.com"],
                 image_match=["prom/prometheus", "quay.io/prometheus/prometheus"]),
]


@dataclass
class Finding:
    component_id: str
    name: str
    repo: str
    purpose: str
    version: str
    evidence: str          # how we found it


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def _semver_from(text: str) -> str | None:
    m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", text or "")
    return m.group(1) if m else None


def _load_clients(kubeconfig: str | None, context: str | None):
    from kubernetes import client, config
    if kubeconfig or context:
        config.load_kube_config(config_file=kubeconfig, context=context)
    else:
        try:
            config.load_incluster_config()      # running as a pod
        except Exception:
            config.load_kube_config(context=context)
    return client.CoreV1Api(), client.AppsV1Api(), client.ApiextensionsV1Api()


def _decode_helm_release(secret_data: str) -> dict | None:
    """Helm release secrets are base64(gzip(json)) — sometimes double-base64."""
    try:
        raw = base64.b64decode(secret_data)
        try:
            raw = base64.b64decode(raw)         # helm double-encodes
        except Exception:
            pass
        data = gzip.decompress(raw)
        return json.loads(data)
    except Exception:
        return None


def discover(kubeconfig: str | None = None, context: str | None = None) -> list[Finding]:
    core, apps, ext = _load_clients(kubeconfig, context)
    by_id: dict[str, Finding] = {}

    def consider(entry: CatalogEntry, version: str | None, evidence: str):
        if not version:
            return
        # prefer Helm evidence (richest) over image/CRD if we already have one
        existing = by_id.get(entry.id)
        if existing and existing.evidence.startswith("helm:"):
            return
        by_id[entry.id] = Finding(entry.id, entry.name, entry.repo,
                                  entry.purpose, version, evidence)

    # ---- pass 1: Helm releases (secrets of type helm.sh/release.v1) ----
    try:
        secrets = core.list_secret_for_all_namespaces(
            field_selector="type=helm.sh/release.v1")
        for s in secrets.items:
            payload = (s.data or {}).get("release")
            rel = _decode_helm_release(payload) if payload else None
            if not rel:
                continue
            chart = (rel.get("chart") or {}).get("metadata") or {}
            chart_name = (chart.get("name") or "").lower()
            version = chart.get("appVersion") or chart.get("version")
            for entry in CATALOG:
                if chart_name in [c.lower() for c in entry.helm_charts]:
                    consider(entry, _semver_from(version),
                             f"helm: chart {chart_name} {version}")
    except Exception as exc:  # noqa: BLE001
        print(f"[discover] helm pass skipped: {exc}", file=sys.stderr)

    # ---- pass 2: workload image tags ----
    try:
        workloads = []
        workloads += apps.list_deployment_for_all_namespaces().items
        workloads += apps.list_stateful_set_for_all_namespaces().items
        workloads += apps.list_daemon_set_for_all_namespaces().items
        for w in workloads:
            containers = (w.spec.template.spec.containers or [])
            for c in containers:
                image = c.image or ""
                for entry in CATALOG:
                    if any(m in image for m in entry.image_match):
                        tag = image.split(":")[-1] if ":" in image else ""
                        consider(entry, _semver_from(tag), f"image: {image}")
    except Exception as exc:  # noqa: BLE001
        print(f"[discover] workload pass skipped: {exc}", file=sys.stderr)

    # ---- pass 3: CRD groups (presence, no version — flags the operator) ----
    try:
        crds = ext.list_custom_resource_definition()
        present_groups = {c.spec.group for c in crds.items}
        for entry in CATALOG:
            if entry.id in by_id:
                continue  # already have a version from helm/image
            if any(g in present_groups for g in entry.crd_groups):
                # CRD tells us it's installed but not the version; flag for review
                by_id[entry.id] = Finding(entry.id, entry.name, entry.repo,
                                          entry.purpose, "UNKNOWN",
                                          f"crd group present (set version manually)")
    except Exception as exc:  # noqa: BLE001
        print(f"[discover] crd pass skipped: {exc}", file=sys.stderr)

    return sorted(by_id.values(), key=lambda f: f.name)


def to_inventory_yaml(findings: list[Finding]) -> str:
    import yaml
    components = [{"id": f.component_id, "name": f.name, "repo": f.repo,
                   "version": f.version, "purpose": f.purpose,
                   "discovered_via": f.evidence} for f in findings]
    doc = {"components": components,
           "platforms": [{"id": "eks", "name": "Amazon EKS", "version": "REVIEW",
                          "purpose": "managed kubernetes",
                          "discovered_via": "set your EKS/k8s version manually"}]}
    header = ("# release-sage inventory — auto-generated by `discover`.\n"
              "# Review versions marked UNKNOWN/REVIEW before relying on the briefing.\n\n")
    return header + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
