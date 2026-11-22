
MITRE_MAPPINGS = {
    "Brute Force Attempt": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "rationale": (
            "Repeated failed login attempts may indicate an attempt "
            "to gain access through password guessing."
        )
    },
    "Multiple Account Targeting": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "rationale": (
            "Attempts against multiple accounts may indicate account "
            "targeting. Additional evidence is needed to identify "
            "a specific brute-force sub-technique."
        )
    },
    "Failed Login Followed by Success": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "rationale": (
            "A successful login following failed attempts may warrant "
            "investigation for possible misuse of valid credentials."
        )
    },
    "Unusual Login Time": {
        "technique_id": None,
        "technique_name": "No direct technique assigned",
        "rationale": (
            "An unusual login time is a contextual indicator, "
            "not sufficient evidence of a specific ATT&CK technique."
        )
    }
}


def get_mitre_mapping(incident_type):
    """Return the MITRE ATT&CK mapping for an incident type."""

    return MITRE_MAPPINGS.get(
        incident_type,
        {
            "technique_id": None,
            "technique_name": "Unmapped",
            "rationale": "No MITRE ATT&CK mapping is currently available."
        }
    )
