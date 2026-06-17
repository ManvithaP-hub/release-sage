"""OSV accuracy-layer tests.

The live api.osv.dev call can only be exercised with network access, so these
tests cover the parts that decide correctness offline: version-range matching
against OSV's event model, and verdict construction from recorded-shape OSV
vuln records. These are the functions that determine "is my version actually
affected", which is the whole point of the layer.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from releasesage import osv  # noqa: E402


def test_version_parsing():
    assert osv.parse_version("v2.11.3") == (2, 11, 3)
    assert osv.parse_version("3.4") == (3, 4, 0)
    assert osv.parse_version("1.12.0-rc.2") == (1, 12, 0)


def test_in_range_introduced_fixed():
    # affected: introduced 2.11.0, fixed 2.11.5  → 2.11.3 is vulnerable
    ranges = [{"events": [{"introduced": "2.11.0"}, {"fixed": "2.11.5"}]}]
    aff, fixed = osv.version_in_ranges("2.11.3", ranges)
    assert aff and fixed == "2.11.5"


def test_outside_range_is_safe():
    # fixed in 2.11.5 → running 2.11.6 is NOT affected
    ranges = [{"events": [{"introduced": "2.11.0"}, {"fixed": "2.11.5"}]}]
    aff, _ = osv.version_in_ranges("2.11.6", ranges)
    assert not aff


def test_below_introduced_is_safe():
    ranges = [{"events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}]}]
    aff, _ = osv.version_in_ranges("2.11.3", ranges)
    assert not aff


def test_last_affected_event():
    ranges = [{"events": [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}]}]
    assert osv.version_in_ranges("1.5.0", ranges)[0] is True
    assert osv.version_in_ranges("1.6.0", ranges)[0] is False


def test_verdict_affected_picks_highest_severity():
    vulns = [
        {"id": "GHSA-low", "severity": [{"score": "4.0"}],
         "affected": [{"ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.12.0"}]}]}]},
        {"id": "CVE-2026-9", "severity": [{"score": "8.1"}],
         "affected": [{"ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.11.5"}]}]}]},
    ]
    v = osv.verdict_from_vulns(vulns, "2.11.3")
    assert v.status == "affected"
    assert v.advisory_id == "CVE-2026-9"   # higher CVSS wins
    assert v.fixed_version == "2.11.5"


def test_verdict_not_affected_when_version_outside_all_ranges():
    vulns = [
        {"id": "CVE-2026-9", "severity": [{"score": "8.1"}],
         "affected": [{"ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.11.5"}]}]}]},
    ]
    v = osv.verdict_from_vulns(vulns, "2.12.0")   # patched
    assert v.status == "not_affected"


def test_assess_unknown_without_mapping():
    v = osv.assess("nonexistent-component", "1.0.0")
    assert v.status == "unknown"
