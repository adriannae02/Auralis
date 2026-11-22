
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from report_generator import generate_incident_reports


def test_generate_incident_reports(tmp_path):
    incidents = [
        {
            "type": "Brute Force Attempt",
            "severity": "HIGH",
            "ip_address": "203.0.113.45",
            "username": "bob",
            "failed_attempts": 5
        }
    ]

    reports = generate_incident_reports(
        incidents,
        output_folder=tmp_path
    )

    assert len(reports) == 1

    report_files = list(tmp_path.glob("*.json"))

    assert len(report_files) == 1

    with report_files[0].open("r", encoding="utf-8") as file:
        saved_report = json.load(file)

    assert saved_report["incident_type"] == "Brute Force Attempt"
    assert saved_report["severity"] == "HIGH"
    assert saved_report["source_ip"] == "203.0.113.45"
    assert saved_report["username"] == "bob"
    assert "recommended_action" in saved_report


def test_generate_empty_reports(tmp_path):
    reports = generate_incident_reports(
        [],
        output_folder=tmp_path
    )

    assert len(reports) == 0
    assert list(tmp_path.glob("*.json")) == []
