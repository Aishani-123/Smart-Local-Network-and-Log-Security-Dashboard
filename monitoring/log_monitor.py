import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque


# Path to the security log file
LOG_FILE = Path(__file__).parent.parent / "logs" / "security.log"

# Store failed login timestamps for each username
failed_login_attempts = defaultdict(deque)

# Brute-force detection settings
TIME_WINDOW = timedelta(seconds=60)
MAX_ATTEMPTS = 3


def analyze_log_line(line):
    """Analyze a log line and identify security events."""

    line = line.strip()

    # Ignore empty lines
    if not line:
        return None

    timestamp = datetime.now(timezone.utc)
    event_type = "normal"
    severity = "low"

    # Detect failed login attempts
    if "FAILED_LOGIN" in line:
        event_type = "failed_login"
        severity = "medium"

        # Extract the username safely
        parts = line.split("user=", 1)

        if len(parts) > 1:
            username_parts = parts[1].split(maxsplit=1)

            if username_parts:
                username = username_parts[0]
                attempts = failed_login_attempts[username]

                # Record the failed login timestamp
                attempts.append(timestamp)

                # Remove attempts older than 60 seconds
                cutoff_time = timestamp - TIME_WINDOW

                while attempts and attempts[0] < cutoff_time:
                    attempts.popleft()

                # Detect possible brute-force activity
                if len(attempts) >= MAX_ATTEMPTS:
                    event_type = "possible_brute_force"
                    severity = "high"

    # Detect access-denied events
    elif "ACCESS_DENIED" in line:
        event_type = "access_denied"
        severity = "high"

    # Detect successful login events
    elif "SUCCESSFUL_LOGIN" in line:
        event_type = "successful_login"
        severity = "low"

    return {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "severity": severity,
        "message": line
    }


def monitor_log():
    """Monitor the security log for newly added entries."""

    print(f"Monitoring log file: {LOG_FILE}")

    # Check whether the log file exists
    if not LOG_FILE.exists():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    # Start at the end of the file
    position = LOG_FILE.stat().st_size

    print("Log monitoring started.")
    print("Waiting for new security events...")
    print("Press Ctrl+C to stop monitoring.")

    try:
        while True:
            # Read newly appended log entries
            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as log_file:
                log_file.seek(position)
                new_lines = log_file.readlines()
                position = log_file.tell()

            # Analyze each new entry
            for line in new_lines:
                event = analyze_log_line(line)

                if event is not None:
                    print(event)

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nLog monitoring stopped.")


if __name__ == "__main__":
    monitor_log()