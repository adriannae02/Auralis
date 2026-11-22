
import re
from pathlib import Path


def parse_log_file(file_path):
    """Read authentication logs and extract login activity."""

    events = []

    log_path = Path(file_path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with log_path.open("r", encoding="utf-8") as log_file:

        for line in log_file:

            if "Failed password" in line:
                status = "FAILED"

            elif "Accepted password" in line:
                status = "SUCCESS"

            else:
                continue

            ip_match = re.search(
                r"from (\d{1,3}(?:\.\d{1,3}){3})",
                line
            )

            user_match = re.search(
                r"(?:for invalid user|for)\s+(\S+)\s+from",
                line
            )

            if ip_match and user_match:
                event = {
                    "username": user_match.group(1),
                    "ip_address": ip_match.group(1),
                    "status": status,
                    "raw_log": line.strip()
                }

                events.append(event)

    return events


if __name__ == "__main__":

    sample_log = Path("data") / "sample_auth.log"

    events = parse_log_file(sample_log)

    print("\nSentinelWatch - Log Analysis Results")
    print("------------------------------------")

    print(f"Total login events detected: {len(events)}")

    for event in events:
        print(event)
