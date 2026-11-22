
import json
from datetime import datetime
from pathlib import Path
from mitre_mapping import get_mitre_mapping

def generate_incident_reports(incidents, output_folder="reports"):
    """Generate individual JSON reports for detected incidents."""

    report_path = Path(output_folder)

    report_path.mkdir(parents=True, exist_ok=True)

    generated_reports = []

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for index, incident in enumerate(incidents, start=1):

        report = {
            "incident_id": f"SW-{timestamp}-{index:03d}",
            "date_generated": datetime.now().isoformat(timespec="seconds"),
            "incident_type": incident["type"],
            "mitre_mapping": get_mitre_mapping(incident["type"]),
            "severity": incident["severity"],
            "source_ip": incident["ip_address"],
            "username": incident.get("username", "Multiple accounts"),
            "evidence": incident,
            "recommended_action": (
                "Investigate the source IP address, review related "
                "authentication activity, and verify whether the "
                "login activity was authorized."
            )
        }

        file_name = f"{report['incident_id']}.json"

        file_path = report_path / file_name

        with file_path.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4)

        generated_reports.append(report)

    return generated_reports


if __name__ == "__main__":
    print("SentinelWatch Incident Report Generator initialized.")
