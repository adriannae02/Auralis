
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_detector import (
    detect_brute_force,
    detect_multiple_account_targeting,
    detect_failed_then_success,
    detect_unusual_login_times
)


def make_event(username, ip, status, time="12:00:00"):
    return {
        "username": username,
        "ip_address": ip,
        "status": status,
        "raw_log": f"Nov 14 {time} server sshd[1000]: test"
    }


def test_brute_force_detection():
    events = [
        make_event("bob", "203.0.113.45", "FAILED")
        for _ in range(5)
    ]

    incidents = detect_brute_force(events)

    assert len(incidents) == 1
    assert incidents[0]["username"] == "bob"


def test_multiple_account_targeting():
    events = [
        make_event("admin", "198.51.100.22", "FAILED"),
        make_event("test", "198.51.100.22", "FAILED"),
        make_event("guest", "198.51.100.22", "FAILED")
    ]

    incidents = detect_multiple_account_targeting(events)

    assert len(incidents) == 1
    assert incidents[0]["account_count"] == 3


def test_failed_then_success():
    events = [
        make_event("charlie", "192.0.2.80", "FAILED"),
        make_event("charlie", "192.0.2.80", "SUCCESS")
    ]

    incidents = detect_failed_then_success(events)

    assert len(incidents) == 1
    assert incidents[0]["username"] == "charlie"


def test_unusual_login_time():
    events = [
        make_event("alice", "192.168.1.10", "SUCCESS", "02:15:22")
    ]

    incidents = detect_unusual_login_times(events)

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "MEDIUM"
