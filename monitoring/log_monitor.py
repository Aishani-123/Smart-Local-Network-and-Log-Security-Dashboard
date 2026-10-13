import time
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict


LOG_FILE = Path(__file__).parent.parent / "logs" / "security.log"
failed_login_counts = defaultdict(int)


def analyze_log_line(line):
    line = line.strip()

    if not line:
        return None

    
    event_type = "normal"
    severity = "low"

    if "FAILED_LOGIN" in line:
        event_type = "failed_login"
        severity = "medium"

        parts = line.split("user=")

        
        if len(parts) > 1:
            username = parts[1].split()[0]

            failed_login_counts[username] += 1

            

            if failed_login_counts[username] >= 3:
                event_type = "possible_brute_force"
                severity = "high"

    elif "ACCESS_DENIED" in line:
        event_type = "access_denied"
        severity = "high"

    elif "SUCCESSFUL_LOGIN" in line:
        event_type = "successful_login"
        severity = "low"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "message": line
    }

def monitor_log():
    print(f"Monitoring log file: {LOG_FILE}")

    position = LOG_FILE.stat().st_size

    while True:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as log_file:
            log_file.seek(position)

            new_lines = log_file.readlines()
            position = log_file.tell()

        for line in new_lines:
            event = analyze_log_line(line)

            if event:
                print(event)

        time.sleep(1)


if __name__ == "__main__":
    monitor_log()