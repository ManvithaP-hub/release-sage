"""Discovery logic tests — verify parsing/matching without a live cluster.

The cluster API calls themselves can only be tested live, but the Helm-secret
decoding, version extraction, and catalog matching are pure functions we can
test against realistic synthetic data.
"""
import base64
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from releasesage import discover as disc  # noqa: E402


def _make_helm_secret_payload(chart_name, version, app_version):
    rel = {"chart": {"metadata": {"name": chart_name, "version": version,
                                  "appVersion": app_version}}}
    blob = gzip.compress(json.dumps(rel).encode())
    # helm double-base64 encodes
    return base64.b64encode(base64.b64encode(blob)).decode()


def test_helm_secret_decodes():
    payload = _make_helm_secret_payload("keda", "2.20.1", "2.20.1")
    rel = disc._decode_helm_release(payload)
    assert rel["chart"]["metadata"]["name"] == "keda"
    assert rel["chart"]["metadata"]["appVersion"] == "2.20.1"


def test_semver_extraction():
    assert disc._semver_from("v2.20.1") == "2.20.1"
    assert disc._semver_from("2.11") == "2.11"
    assert disc._semver_from("kyverno-chart-3.8.1-rc.2") == "3.8.1"
    assert disc._semver_from("no version here") is None


def test_catalog_recognizes_known_tools():
    ids = {e.id for e in disc.CATALOG}
    assert {"keda", "argocd", "external-secrets", "kyverno"} <= ids
    keda = next(e for e in disc.CATALOG if e.id == "keda")
    assert "keda.sh" in keda.crd_groups
    assert keda.repo == "kedacore/keda"


def test_inventory_yaml_roundtrip():
    import yaml
    findings = [disc.Finding("keda", "KEDA", "kedacore/keda",
                             "autoscaling", "2.20.1", "helm: chart keda 2.20.1")]
    text = disc.to_inventory_yaml(findings)
    parsed = yaml.safe_load(text)
    assert parsed["components"][0]["id"] == "keda"
    assert parsed["components"][0]["version"] == "2.20.1"
    assert "discovered_via" in parsed["components"][0]
