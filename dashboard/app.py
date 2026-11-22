import streamlit as st
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_parser import parse_log_file
from threat_detector import (
    detect_brute_force,
    detect_multiple_account_targeting,
    detect_failed_then_success,
    detect_unusual_login_times
)
from mitre_mapping import get_mitre_mapping

# Load authentication log data
LOG_FILE = Path(__file__).resolve().parents[1] / "data" / "sample_auth.log"

events = parse_log_file(LOG_FILE)


# Run threat detection methods
brute_force_incidents = detect_brute_force(events)

account_targeting_incidents = detect_multiple_account_targeting(events)

failed_then_success_incidents = detect_failed_then_success(events)

unusual_time_incidents = detect_unusual_login_times(events)

# Combine all detected incidents
all_incidents = (
    brute_force_incidents
    + account_targeting_incidents
    + failed_then_success_incidents
    + unusual_time_incidents
)

# Calculate incident severity totals
high_severity = sum(
    1 for incident in all_incidents
    if incident["severity"] == "HIGH"
)

medium_severity = sum(
    1 for incident in all_incidents
    if incident["severity"] == "MEDIUM"
)

low_severity = sum(
    1 for incident in all_incidents
    if incident["severity"] == "LOW"
)
# Calculate login statistics
total_logins = len(events)

successful_logins = sum(
    1 for event in events if event["status"] == "SUCCESS"
)

failed_logins = sum(
    1 for event in events if event["status"] == "FAILED"
)

# Configure the dashboard page
st.set_page_config(
    page_title="Auralis",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar
with st.sidebar:
    st.title("✧ AURALIS")
    st.caption("Security Monitoring Platform")

    st.markdown("---")

    st.subheader("About Auralis")
    st.write(
        "A security monitoring tool designed to "
        "analyze authentication logs and identify "
        "potentially suspicious activity."
    )

    st.markdown("---")

    st.subheader("Detection Rules")
    st.write("🔴 Brute Force Attempts")
    st.write("🔴 Multiple Account Targeting")
    st.write("🔴 Failed Login Followed by Success")
    st.write("🟡 Unusual Login Times")

    st.markdown("---")

    st.caption("Educational cybersecurity project")

# Dashboard title
st.title("✧ AURALIS")
st.subheader("Security Log Monitoring & Threat Detection")

# System status
st.markdown(
    "🟢 **SYSTEM STATUS: OPERATIONAL** "
    "| Log Monitoring: Active "
    "| Threat Detection: Enabled"
)
st.caption(
    f"Dashboard refreshed: {datetime.now().strftime('%B %d, %Y at %I:%M:%S %p')}"
)
from datetime import datetime
st.markdown("---")

# Dashboard introduction
st.write(
    "Welcome to Auralis! This dashboard monitors "
    "authentication activity and identifies potentially "
    "suspicious login behavior."
)

# Summary metrics
st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Login Events", total_logins)

with col2:
    st.metric("Successful Logins", successful_logins)

with col3:
    st.metric("Failed Logins", failed_logins)

with col4:
    st.metric("Suspicious Incidents", len(all_incidents))

# Login activity chart
st.subheader("Authentication Activity")

login_chart_data = {
    "Login Status": ["Successful", "Failed"],
    "Count": [successful_logins, failed_logins]
}

st.bar_chart(
    login_chart_data,
    x="Login Status",
    y="Count"
)

st.markdown("---")

# Severity breakdown
st.subheader("Incident Severity Breakdown")

sev_col1, sev_col2, sev_col3 = st.columns(3)

with sev_col1:
    st.metric("🔴 High Severity", high_severity)

with sev_col2:
    st.metric("🟡 Medium Severity", medium_severity)

with sev_col3:
    st.metric("🟢 Low Severity", low_severity)

st.markdown("---")

# Incident Severity Chart
st.subheader("Incident Severity Distribution")

severity_chart_data = {
    "Severity": ["High", "Medium", "Low"],
    "Incidents": [
        high_severity,
        medium_severity,
        low_severity
    ]
}

st.bar_chart(
    severity_chart_data,
    x="Severity",
    y="Incidents",
    color="Severity"
)

# Incident section
st.markdown("---")
st.subheader("Detected Security Incidents")

if all_incidents:
    for index, incident in enumerate(all_incidents, start=1):

        severity = incident["severity"]

        if severity == "HIGH":
            severity_icon = "🔴"
        elif severity == "MEDIUM":
            severity_icon = "🟡"
        else:
            severity_icon = "🟢"

        with st.expander(
            f"{index}. {severity_icon} {incident['type']} - {severity}"
        ):
            st.write(f"**Source IP:** {incident['ip_address']}")

            st.write(
                f"**Username:** "
                f"{incident.get('username', 'Multiple accounts')}"
            )

            # Display MITRE ATT&CK information
            mitre_info = get_mitre_mapping(incident["type"])

            st.write("**MITRE ATT&CK Mapping**")

            if mitre_info["technique_id"]:
                st.write(
                    f"**Technique ID:** {mitre_info['technique_id']}"
                )

            st.write(
                f"**Technique:** {mitre_info['technique_name']}"
            )

            st.write(
                f"**Rationale:** {mitre_info['rationale']}"
            )

            st.json(incident)

else:
    st.success("No suspicious incidents detected.")
