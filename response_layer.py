"""Risk ratings and demonstration-only response logging."""
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
ACTION_LOG = LOG_DIR / "response_actions.jsonl"


ANOMALY_SCORE_THRESHOLD = 0.05
HIGH_ANOMALY_SCORE = -0.30
HIGH_CPU_LIMIT = 90.0
DEMO_CPU_LIMIT = 70.0


def classify_risk(anomaly_score=1.0, severity="low", cpu_usage=0,
                  network_connections=0, sustained_high_cpu=False):
    score = float(anomaly_score if anomaly_score is not None else 1.0)
    severity = str(severity or "low").lower()
    cpu = float(cpu_usage or 0)
    
    if severity == "high" or (score <= HIGH_ANOMALY_SCORE and cpu >= HIGH_CPU_LIMIT and sustained_high_cpu):
        return "high"
    if severity == "medium" or score < ANOMALY_SCORE_THRESHOLD or cpu >= DEMO_CPU_LIMIT:
        return "medium"
    return "low"


def risk_reason(anomaly_score=1.0, severity="low", cpu_usage=0,
                network_connections=0, sustained_high_cpu=False):
    score = float(anomaly_score if anomaly_score is not None else 1.0)
    severity = str(severity or "low").lower()
    cpu = float(cpu_usage or 0)
    if severity == "high":
        return "Repeated high-severity security events need urgent review."
    if score <= HIGH_ANOMALY_SCORE and cpu >= HIGH_CPU_LIMIT and sustained_high_cpu:
        return f"Strong anomaly score ({score:.3f}) and sustained CPU use ({cpu:.0f}%)."
    if cpu >= DEMO_CPU_LIMIT:
        
        return f"High CPU usage."
    if score < ANOMALY_SCORE_THRESHOLD:
        return f"Unusual score ({score:.3f}); flagged for review."
    if severity == "medium":
        return "Security event flagged for review."
    return "Activity is within the normal range."


def classify_network_health(processes, log_events, connections):
    high_processes = sum(p.get("risk") == "high" for p in processes)
    medium_processes = sum(p.get("risk") == "medium" for p in processes)
    brute_force = sum(e.get("event_type") == "possible_brute_force" for e in log_events)
    log_attention = any(e.get("severity") in ("medium", "high") for e in log_events)
    active_remote = sum(bool(c.get("destination_ip")) and c.get("status") == "ESTABLISHED"
                        for c in connections)
    
    if high_processes >= 2 or brute_force >= 3 or (active_remote >= 250 and high_processes >= 1):
        return "HIGH", "Multiple severe process indicators or repeated failed logins."
    if high_processes or medium_processes or log_attention or active_remote >= 100:
        return "MEDIUM", f"Activity needs attention: {active_remote} established remote connections; no automatic action was taken."
    return "LOW", "No strong risk indicators were found in the current scan."
def _append_action(entry):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with ACTION_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")
    return entry


def handle_event(event, requested_by="system", admin_confirmed=False):
    risk = classify_risk(event.get("anomaly_score", 1.0), event.get("severity", "low"),
                         event.get("cpu_usage", 0), event.get("network_connections", 0),
                         event.get("sustained_high_cpu", False))
    return _append_action({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": event.get("pid"), "process_name": event.get("process_name"),
        "anomaly_score": event.get("anomaly_score"), "severity": risk,
        "action": "flagged_for_review" if risk != "low" else "none",
        "executed": False
    })


def handle_demo_removal(event):
    """Log a visual demo response only; this deliberately never signals a process."""
    return _append_action({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": event.get("pid"), "process_name": event.get("process_name"),
        "anomaly_score": event.get("anomaly_score"), "severity": event.get("risk", "medium"),
        "action": "demo_removal_shown", "executed": False,
    })


       
    
        

    
        
   
