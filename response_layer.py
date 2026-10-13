import os
import json
import ipaddress
import subprocess
import psutil
from pathlib import Path
from datetime import datetime, timezone 
LOG_DIR = Path(__file__).parent / "logs"
ACTION_LOG = LOG_DIR / "response_actions.log"
DRY_RUN = True 
AUTHORIZED_ADMINS = ["admin", "aishani"] 
PROTECTED_PROCESSES = [
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "init",
    "systemd", "kthreadd", "sshd", "postgres",
    "postgres.exe", "python", "python.exe", "python3"
] 
SAFE_IPS = ["127.0.0.1", "0.0.0.0", "::1"]
LOWER_PRIORITY_SCORE = -0.05
TERMINATE_SCORE = -0.15
HIGH_CPU_LIMIT = 80
def now():
    return datetime.now(timezone.utc).isoformat()
def write_action_log(entry):
    LOG_DIR.mkdir(parents=True, exist_ok=True) 
    with open(ACTION_LOG, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n") 
def is_authorized(user):
    if not isinstance(user, str):
        return False
    for admin in AUTHORIZED_ADMINS:
        if admin.lower() == user.lower():
            return True
    return False
def is_protected_process(pid, process_name):
    if pid is None:
        return True
    if pid == os.getpid() or pid == os.getppid():
        return True
    if pid <= 4:
        return True
    if process_name and process_name.lower() in PROTECTED_PROCESSES:
        return True
    return False
def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if ip in SAFE_IPS:
        return False
    if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    return True
def decide_response(event):
    pid = event.get("pid")
    process_name = event.get("process_name")
    score = event.get("anomaly_score", 0)
    severity = str(event.get("severity", "low")).lower()
    cpu = event.get("cpu_usage", 0)
    ip = event.get("destination_ip")
    decision = {
        "action": "none",
        "approved": False,
        "needs_admin_approval": False,
        "reason": "Normal event. No action needed."
    }
    if score >= 0 and severity == "low":
        return decision
    if is_protected_process(pid, process_name):
        decision["action"] = "alert_only"
        decision["reason"] = "Protected or system process. Alert only."
        return decision
    if score <= TERMINATE_SCORE and severity == "high":
        decision["action"] = "terminate_process"
        decision["approved"] = True
        decision["needs_admin_approval"] = True
        decision["reason"] = "Very high anomaly score and high severity."
    elif severity == "high" and is_valid_ip(ip):
        decision["action"] = "block_ip"
        decision["approved"] = True
        decision["needs_admin_approval"] = True
        decision["reason"] = "High severity event from IP " + str(ip)
    elif score <= LOWER_PRIORITY_SCORE and cpu >= HIGH_CPU_LIMIT:
        decision["action"] = "lower_priority"
        decision["approved"] = True
        decision["reason"] = "Suspicious process with high CPU usage."
    else:
        decision["action"] = "alert_only"
        decision["reason"] = "Suspicious event. Further review needed."
    return decision
def lower_priority(pid):
    try:
        proc = psutil.Process(pid)
        if os.name == "nt":
            proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            proc.nice(10)
        return True, "Process priority lowered."
    except (psutil.Error, OSError) as e:
        return False, "Could not lower priority: " + str(e) 
def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        return True, "Process terminated."
    except (psutil.Error, OSError) as e:
        return False, "Could not terminate process: " + str(e) 
def block_ip(ip):
    if not is_valid_ip(ip):
        return False, "Invalid or protected IP address."
    rule_name = "SecurityDashboard_Block_" + ip
    if os.name == "nt":
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + rule_name,
            "dir=out", "action=block", "remoteip=" + ip
        ]
    elif os.name == "posix" and Path("/usr/sbin/iptables").exists():
        command = ["/usr/sbin/iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
    else:
        return False, "Firewall blocking is not configured for this operating system."
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, "Firewall rule added."
        return False, "Firewall command failed: " + result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, "Could not run firewall command: " + str(e)
def execute_action(event, decision):
    action = decision["action"]
    if DRY_RUN:
        action_name = action.replace("_", " ")
        return True, "DRY RUN: " + action_name + " simulated; no system change made."
    if action == "lower_priority":
        return lower_priority(event["pid"])
    if action == "terminate_process":
        return terminate_process(event["pid"])
    if action == "block_ip":
        return block_ip(event["destination_ip"])
    return True, "No system change needed." 
def handle_event(event, requested_by="system", admin_confirmed=False):
    decision = decide_response(event)
    executed = False
    message = decision["reason"]
    if decision["action"] not in ("none", "alert_only"):
        if not decision["approved"]:
            message = "Action rejected by security policy."
        elif decision["needs_admin_approval"] and not is_authorized(requested_by):
            message = "Unauthorized user: " + str(requested_by) + ". Action rejected."
        elif decision["needs_admin_approval"] and not admin_confirmed:
            message = "Waiting for administrator confirmation."
        else:
            executed, message = execute_action(event, decision)
    entry = {
        "timestamp": now(),
        "pid": event.get("pid"),
        "process_name": event.get("process_name"),
        "anomaly_score": event.get("anomaly_score"),
        "severity": event.get("severity"),
        "action": decision["action"],
        "needs_admin_approval": decision["needs_admin_approval"],
        "requested_by": requested_by,
        "executed": executed,
        "dry_run": DRY_RUN,
        "message": message
    }
    write_action_log(entry)
    return entry 
def print_header():
    if DRY_RUN:
        mode = "DRY RUN - SAFE TESTING"
        changes = "DISABLED"
    else:
        mode = "LIVE MODE"
        changes = "ENABLED"
    print("\n" + "=" * 64)
    print("              SMART NETWORK SECURITY")
    print("                   RESPONSE LAYER")
    print("=" * 64)
    print("  Mode             : " + mode)
    print("  Actual changes   : " + changes)
    print("=" * 64) 
def print_event_result(number, result):
    action = result["action"].replace("_", " ").upper()
    severity = str(result.get("severity") or "unknown").upper()
    process_name = result.get("process_name") or "Unknown"
    if result["needs_admin_approval"]:
        approval = "Required"
    else:
        approval = "Not required" 
    if result["action"] == "none":
        status = "NORMAL"
    elif "Unauthorized user" in result["message"]:
        status = "REJECTED - UNAUTHORIZED"
    elif "Waiting for administrator" in result["message"]:
        status = "PENDING ADMIN APPROVAL"
    elif result["action"] == "alert_only":
        status = "ALERT ONLY"
    elif result["dry_run"] and result["executed"]:
        status = "SIMULATED - NO SYSTEM CHANGE"
    elif result["executed"]:
        status = "ACTION EXECUTED"
    else:
        status = "ACTION FAILED / NOT EXECUTED"
    print("\n" + "-" * 64)
    print(f"  EVENT #{number}  |  SEVERITY: {severity}")
    print("-" * 64)
    print(f"  Process          : {process_name}")
    print(f"  PID              : {result.get('pid')}")
    print(f"  Anomaly Score    : {result.get('anomaly_score')}")
    print(f"  Action Selected  : {action}")
    print(f"  Admin Approval   : {approval}")
    print(f"  Status           : {status}")
    print(f"  Explanation      : {result['message']}")
def print_summary(results):
    normal = 0
    alerts = 0
    priority = 0
    terminate = 0
    block = 0
    pending = 0
    rejected = 0
    simulated = 0
    for result in results:
        action = result["action"]
        if action == "none":
            normal += 1
        elif action == "alert_only":
            alerts += 1
        elif action == "lower_priority":
            priority += 1
        elif action == "terminate_process":
            terminate += 1
        elif action == "block_ip":
            block += 1
        if "Waiting for administrator" in result["message"]:
            pending += 1
        if "Unauthorized user" in result["message"]:
            rejected += 1
        if result["dry_run"] and result["executed"]:
            if action not in ("none", "alert_only"):
                simulated += 1
    print("\n" + "=" * 64)
    print("                     TEST SUMMARY")
    print("=" * 64)
    print(f"  Total events processed  : {len(results)}")
    print(f"  Normal events           : {normal}")
    print(f"  Alert-only events       : {alerts}")
    print(f"  Priority decisions      : {priority}")
    print(f"  Termination decisions   : {terminate}")
    print(f"  IP blocking decisions   : {block}")
    print(f"  Pending admin approvals : {pending}")
    print(f"  Unauthorized requests   : {rejected}")
    print(f"  Simulated actions       : {simulated}")
    print(f"  Log file                : {ACTION_LOG}")
    print("=" * 64)
    print("  Response Layer test completed.")
    print("=" * 64 + "\n")
if __name__ == "__main__":
    test_events = [
        {
            "pid": 5000,
            "process_name": "chrome.exe",
            "anomaly_score": 0.12,
            "severity": "low",
            "cpu_usage": 10,
            "destination_ip": None
        },
        {
            "pid": 5001,
            "process_name": "miner.exe",
            "anomaly_score": -0.08,
            "severity": "medium",
            "cpu_usage": 95,
            "destination_ip": None
        },
        {
            "pid": 5002,
            "process_name": "unknown.exe",
            "anomaly_score": -0.22,
            "severity": "high",
            "cpu_usage": 60,
            "destination_ip": "45.33.12.9"
        },
        {
            "pid": 4,
            "process_name": "System",
            "anomaly_score": -0.30,
            "severity": "high",
            "cpu_usage": 5,
            "destination_ip": None
        }
    ]
    results = []
    print_header()
    for number, event in enumerate(test_events, start=1):
        result = handle_event(event, requested_by="admin")
        results.append(result)
        print_event_result(number, result)
    print("\n  ADMIN CONFIRMATION TEST")
    print("  " + "-" * 40)
    confirmed_result = handle_event(test_events[2], requested_by="admin", admin_confirmed=True)
    results.append(confirmed_result)
    print_event_result(len(results), confirmed_result)
    print("\n  UNAUTHORIZED USER TEST")
    print("  " + "-" * 40)
    unauthorized_result = handle_event(test_events[2], requested_by="guest", admin_confirmed=True)
    results.append(unauthorized_result)
    print_event_result(len(results), unauthorized_result)
    print_summary(results)
 
