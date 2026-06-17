"""release-sage contract tests."""
import sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from releasesage import gate, inventory as inv  # noqa: E402
from releasesage.models import RawItem, Source  # noqa: E402

POLICY = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())
INV = inv.load_inventory(str(ROOT / "config" / "inventory.yaml"))
# Keep classifier tests offline & deterministic: OSV lookups are tested
# separately in test_osv.py against recorded response shapes.
POLICY["osv"] = {"enabled": False}


def _raw(title, summary="", sid="keda-releases"):
    return RawItem(source_id=sid, title=title, url="https://x", summary=summary)


def _src(sid="keda-releases", component="keda", kind="github_releases"):
    return Source(id=sid, name=sid, url="https://x", tier="primary",
                  kind=kind, component=component)


def test_cve_for_owned_component_is_patch_now():
    cls = inv.classify_release(
        _raw("Argo CD path traversal (CVE-2026-1) CVSS 8.1, patched in 2.11.5",
             "high severity, affects versions before 2.11.5", "argocd-ghsa"),
        _src("argocd-ghsa", "argocd", "github_security"), INV, POLICY)
    assert cls.signal_label == "patch_now"
    assert cls.urgency >= 80


def test_breaking_change_is_upgrade_planning():
    cls = inv.classify_release(
        _raw("KEDA v2.16.0 breaking change to ScaledObject API",
             "removes deprecated fields; you must migrate manifests", "keda-releases"),
        _src("keda-releases", "keda"), INV, POLICY)
    assert cls.signal_label == "upgrade_planning"


def test_component_not_in_inventory_is_noise():
    cls = inv.classify_release(
        _raw("cert-manager v1.15 released", "routine release of cert-manager"),
        _src("keda-releases", "keda"), INV, POLICY)
    assert cls.signal_label == "noise"
    assert cls.substance == 0


def test_already_on_version_is_not_actionable():
    cls = inv.classify_release(
        _raw("KEDA v2.14.0", "maintenance release"),
        _src("keda-releases", "keda"), INV, POLICY)
    assert cls.substance == 0  # you're already on 2.14.0


def test_quiet_window_suppressed():
    items_raw = [(_src("keda-releases", "keda"), _raw("KEDA v2.14.0", "maintenance")),
                 (_src("argocd-releases", "argocd"),
                  _raw("Argo CD v2.11.3", "patch, no security, no breaking"))]
    from releasesage.models import Item
    items = [Item(raw=r, source=s, cls=inv.classify_release(r, s, INV, POLICY))
             for s, r in items_raw]
    gate.thread_and_score_novelty(items, [], POLICY)
    gate.corroborate(items, [])
    d = gate.apply_gate(items, POLICY)
    assert not d.published


def test_release_with_patch_word_is_not_security():
    # 'patch' in ordinary release notes must NOT trigger a security label
    cls = inv.classify_release(
        _raw("Argo CD v3.4.3", "patch release with bug fixes and minor improvements"),
        _src("argocd-releases", "argocd"), INV, POLICY)
    assert cls.category != "security"
    assert cls.signal_label not in ("patch_now", "security_review")


def test_real_cve_id_triggers_security():
    cls = inv.classify_release(
        _raw("Argo CD advisory GHSA-aaaa-bbbb-cccc (CVE-2026-9999)",
             "high severity path traversal, patched in 3.4.5", "argocd-ghsa"),
        _src("argocd-ghsa", "argocd", "github_security"), INV, POLICY)
    assert cls.category == "security"


def test_osv_confirmed_affected_overrides_version_gap():
    """OSV authoritative 'affected' must beat the semver already-covered cap."""
    from unittest.mock import patch
    from releasesage import osv
    raw = _raw("GHSA-aaaa-bbbb-cccc Argo CD flaw CVE-2026-1111",
               "affects versions before 3.3.0", "argocd-ghsa")
    src = _src("argocd-ghsa", "argocd", "github_security")
    pol = dict(POLICY); pol["osv"] = {"enabled": True}
    with patch.object(osv, "assess", return_value=osv.OSVVerdict(
            status="affected", advisory_id="CVE-2026-1111", cvss_score=8.1,
            severity="high", fixed_version="3.3.5")):
        c = inv.classify_release(raw, src, INV, pol)
    assert c.signal_label == "patch_now"
    assert c.urgency >= 80


def test_osv_not_affected_silences_alarm():
    """OSV 'not_affected' turns a CVE-bearing item into noise (no busywork)."""
    from unittest.mock import patch
    from releasesage import osv
    raw = _raw("GHSA-aaaa-bbbb-cccc Argo CD flaw CVE-2026-1111",
               "affects versions before 3.3.0", "argocd-ghsa")
    src = _src("argocd-ghsa", "argocd", "github_security")
    pol = dict(POLICY); pol["osv"] = {"enabled": True}
    with patch.object(osv, "assess", return_value=osv.OSVVerdict(
            status="not_affected", summary="3.3.0 not in any affected range")):
        c = inv.classify_release(raw, src, INV, pol)
    assert c.signal_label == "noise"
