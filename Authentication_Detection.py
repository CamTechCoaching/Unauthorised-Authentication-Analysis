"""
Authentication Log Analysis
Detects:
- Logins from non-approved geographic locations
- Excessive failed login attempts suggesting brute-force activity
"""

import json
import re
import datetime
from collections import defaultdict

# ---------------------------------------------------------
# CONFIGURATION SECTION
# These settings define expected behavior and security policy
# ---------------------------------------------------------

# Mock internal IP to Country lookup table.
# In a production environment, replace with a GeoIP service lookup.
IP_COUNTRY_MAP = {
    "192.168.1.5": "United States",   # Expected login region for user "john"
    "10.0.0.2": "Germany",            # Expected login region for user "alice"
    "83.244.23.11": "Russia"          # Suspicious external IP example
}

# Approved login country per user
# Used to detect credential misuse from unexpected locations
APPROVED_COUNTRIES = {
    "john": ["United States"],
    "alice": ["Germany"]
}

# Threshold for flagging repeated failed login attempts as suspicious
FAILED_ATTEMPT_THRESHOLD = 3

# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def resolve_country(ip_address):
    """
    Determine country for an IP.
    Falls back to 'Unknown' if no mapping exists.
    In production, integrate with a geo-IP lookup provider.
    """
    return IP_COUNTRY_MAP.get(ip_address, "Unknown")


def parse_log_line(log_line):
    """
    Parse log entries with the structure:
    YYYY-MM-DD HH:MM:SS IP=x.x.x.x USER=username ACTION=LOGIN_FAIL or LOGIN_SUCCESS
    
    Returns a dictionary if format matches, otherwise None.
    """
    pattern = (
        r'(?P<timestamp>[\d\-]+\s[\d:]+)\s'
        r'IP=(?P<ip>[\d.]+)\s'
        r'USER=(?P<username>\w+)\s'
        r'ACTION=(?P<action>\w+)'
    )
    match = re.match(pattern, log_line)
    return match.groupdict() if match else None


def analyze_logs(log_file_path):
    """
    Core detection logic:
    - Tracks login activity per user and IP
    - Flags successful logins from unapproved regions
    - Flags excessive failed attempts suggesting intrusion attempts
    """
    alerts = []                                   # Stores detected security events
    failed_attempts = defaultdict(int)            # Failed login count per (user, IP)
    activity_history = defaultdict(list)          # Track actions for context
    successful_logins = set()                     # Track successful login pairs

    with open(log_file_path, "r") as file:
        for line in file:
            entry = parse_log_line(line.strip())
            if not entry:
                continue  # Skip non-matching entries

            user = entry["username"]
            ip = entry["ip"]
            action = entry["action"]
            country = resolve_country(ip)

            # Log action for auditing and context
            activity_history[(user, ip)].append(action)

            # Count failed login attempts to identify brute-force behavior
            if action == "LOGIN_FAIL":
                failed_attempts[(user, ip)] += 1

            # On successful login, verify geographic legitimacy
            elif action == "LOGIN_SUCCESS":
                successful_logins.add((user, ip))
                if country not in APPROVED_COUNTRIES.get(user, []):
                    alerts.append({
                        "user": user,
                        "ip": ip,
                        "country": country,
                        "issue": "Login from unapproved location (possible credential compromise)",
                        "activity_log": activity_history[(user, ip)]
                    })

    # After scanning all logs, evaluate brute-force attempts
    for (user, ip), count in failed_attempts.items():
        if count >= FAILED_ATTEMPT_THRESHOLD:
            alerts.append({
                "user": user,
                "ip": ip,
                "country": resolve_country(ip),
                "issue": f"{count} failed login attempts detected (possible brute-force attack)",
                "activity_log": activity_history[(user, ip)]
            })

    return alerts


def save_results(results):
    """
    Saves the analysis results to a timestamped JSON file for records or SOC review.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"Unauthorized_Access_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to: {filename}")


# ---------------------------------------------------------
# MAIN EXECUTION LOGIC
# ---------------------------------------------------------

if __name__ == "__main__":
    log_file = "access.log"  # Replace with syslog or SIEM feed in real deployments
    results = analyze_logs(log_file)

    if results:
        save_results(results)
    else:
        print("No unauthorized access detected.")
