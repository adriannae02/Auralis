from collections import defaultdict
from datetime import datetime
from pathlib import Path

from log_parser import parse_log_file
from report_generator import generate_incident_reports

def detect_brute_force(events, threshold=5):
    """Identify repeated failed login attempts for the same user and IP."""

    failed_attempts = defaultdict(list)

    for event in events:

        if event["status"] == "FAILED":
            key = (event["ip_address"], event["username"])
            failed_attempts[key].append(event)

    incidents = []

    for (ip_address, username), attempts in failed_attempts.items():

        if len(attempts) >= threshold:

            incident = {
                "type": "Brute Force Attempt",
                "severity": "HIGH",
                "ip_address": ip_address,
                "username": username,
                "failed_attempts": len(attempts),
                "description": (
                    f"{len(attempts)} failed login attempts "
                    f"detected for user {username} "
                    f"from IP address {ip_address}."
                )
            }

            incidents.append(incident)

    return incidents


def detect_multiple_account_targeting(events, threshold=3):
    """Identify IP addresses attempting to access multiple accounts."""

    targeted_accounts = defaultdict(set)

    for event in events:

        if event["status"] == "FAILED":
            ip_address = event["ip_address"]
            username = event["username"]

            targeted_accounts[ip_address].add(username)

    incidents = []

    for ip_address, usernames in targeted_accounts.items():

        if len(usernames) >= threshold:

            incident = {
                "type": "Multiple Account Targeting",
                "severity": "HIGH",
                "ip_address": ip_address,
                "targeted_accounts": sorted(usernames),
                "account_count": len(usernames),
                "description": (
                    f"IP address {ip_address} attempted to access "
                    f"{len(usernames)} different accounts."
                )
            }

            incidents.append(incident)

    return incidents


def detect_failed_then_success(events):
    """Identify failed logins followed by a successful login."""

    failed_logins = set()
    reported_incidents = set()

    incidents = []

    for event in events:

        key = (event["ip_address"], event["username"])

        if event["status"] == "FAILED":
            failed_logins.add(key)

        elif event["status"] == "SUCCESS" and key in failed_logins:

            if key not in reported_incidents:

                incident = {
                    "type": "Failed Login Followed by Success",
                    "severity": "HIGH",
                    "ip_address": event["ip_address"],
                    "username": event["username"],
                    "description": (
                        f"User {event['username']} had a failed login "
                        f"followed by a successful login from "
                        f"{event['ip_address']}."
                    )
                }

                incidents.append(incident)
                reported_incidents.add(key)

    return incidents



def detect_unusual_login_times(events, start_hour=6, end_hour=22):
    """Identify successful logins outside normal monitoring hours."""

    incidents = []

    for event in events:

        if event["status"] != "SUCCESS":
            continue

        raw_log = event["raw_log"]

        try:
            timestamp_text = raw_log.split()[2]
            login_time = datetime.strptime(timestamp_text, "%H:%M:%S")

            if login_time.hour < start_hour or login_time.hour >= end_hour:

                incident = {
                    "type": "Unusual Login Time",
                    "severity": "MEDIUM",
                    "ip_address": event["ip_address"],
                    "username": event["username"],
                    "login_time": timestamp_text,
                    "description": (
                        f"Successful login for {event['username']} "
                        f"occurred at an unusual time: {timestamp_text}."
                    )
                }

                incidents.append(incident)

        except (IndexError, ValueError):
            continue

    return incidents

if __name__ == "__main__":

    sample_log = Path("data") / "sample_auth.log"

    events = parse_log_file(sample_log)

    brute_force_incidents = detect_brute_force(events)

    account_targeting_incidents = detect_multiple_account_targeting(events)

    failed_then_success_incidents = detect_failed_then_success(events)

    unusual_time_incidents = detect_unusual_login_times(events)

    all_incidents = (
        brute_force_incidents
        + account_targeting_incidents
        + failed_then_success_incidents
        + unusual_time_incidents
)

    print(f"Total suspicious incidents detected: {len(all_incidents)}")

    for incident in all_incidents:
        print(incident)

    generated_reports = generate_incident_reports(all_incidents)

    print(f"\nIncident reports generated: {len(generated_reports)}")
    print("Reports saved in the reports folder.")