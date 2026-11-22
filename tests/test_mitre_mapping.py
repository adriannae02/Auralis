
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mitre_mapping import get_mitre_mapping


def test_brute_force_mapping():
    mapping = get_mitre_mapping("Brute Force Attempt")

    assert mapping["technique_id"] == "T1110"
    assert mapping["technique_name"] == "Brute Force"


def test_failed_then_success_mapping():
    mapping = get_mitre_mapping("Failed Login Followed by Success")

    assert mapping["technique_id"] == "T1078"
    assert mapping["technique_name"] == "Valid Accounts"


def test_unusual_login_time_has_no_direct_mapping():
    mapping = get_mitre_mapping("Unusual Login Time")

    assert mapping["technique_id"] is None


def test_unknown_incident_type():
    mapping = get_mitre_mapping("Unknown Incident")

    assert mapping["technique_name"] == "Unmapped"
