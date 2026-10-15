import os
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
HISTORY_FILE = DATA_DIR / "process_history.csv"
MODEL_FILE = DATA_DIR / "process_anomaly_model.pkl"
BASE_FEATURES = [
    "process_size_mb", "memory_usage_mb", "cpu_usage", "execution_time_sec",
    "thread_count", "network_connections", "bytes_sent_mb", "failed_accesses",
    "file_operations",
]


def prepare_features(data):
    data = data.copy()
    size = data["process_size_mb"].clip(lower=0.1)
    data["memory_size_ratio"] = data["memory_usage_mb"] / size
    data["time_size_ratio"] = data["execution_time_sec"] / size
    data["network_per_thread"] = data["network_connections"] / data["thread_count"].clip(lower=1)
    data["data_per_connection"] = data["bytes_sent_mb"] / data["network_connections"].clip(lower=1)
    return data.replace([np.inf, -np.inf], np.nan).fillna(0)


def get_process_record(proc, cpu_interval=None):
    try:
        with proc.oneshot():
            pid = proc.pid
            memory = proc.memory_info().rss / (1024 * 1024)
            cpu = proc.cpu_percent(interval=cpu_interval)
            threads = proc.num_threads()
            age = max(0.0, time.time() - proc.create_time())
            try:
                executable = proc.exe()
                size = os.path.getsize(executable) / (1024 * 1024) if executable and os.path.isfile(executable) else 0.1
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                size = 0.1
            try:
                connections = len(proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                connections = 0
            name = proc.name()
        return {
            "pid": pid, "process_name": name,
            "process_size_mb": max(size, 0.1), "memory_usage_mb": memory,
            "cpu_usage": cpu, "execution_time_sec": age,
            "thread_count": max(threads, 1), "network_connections": connections,
            "bytes_sent_mb": 0.0, "failed_accesses": 0, "file_operations": 0,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None


class ProcessAnomalyDetector:
    """Lazily train once from live process records and reuse the saved model."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.model = self._load_or_train()

    def _collect_history(self):
        records = []
        for proc in psutil.process_iter():
            record = get_process_record(proc)
            if record:
                records.append(record)
        frame = pd.DataFrame(records)
        if frame.empty:
            raise RuntimeError("No accessible processes were available to create a model baseline.")
        frame = frame[BASE_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
        if len(frame) < 10:
            # A small local system can still run the demo; bootstrap repeated baseline rows.
            frame = pd.concat([frame] * max(1, (10 + len(frame) - 1) // max(len(frame), 1)), ignore_index=True)
        frame.to_csv(HISTORY_FILE, index=False)
        return frame

    def _load_or_train(self):
        if MODEL_FILE.exists():
            try:
                model = joblib.load(MODEL_FILE)
                if getattr(model, "n_features_in_", None) == len(BASE_FEATURES) + 4:
                    return model
            except (OSError, ValueError, EOFError, AttributeError):
                pass
        if HISTORY_FILE.exists():
            try:
                history = pd.read_csv(HISTORY_FILE)
                if all(name in history.columns for name in BASE_FEATURES) and len(history) >= 10:
                    history = history[BASE_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
                else:
                    history = self._collect_history()
            except (OSError, ValueError, pd.errors.ParserError):
                history = self._collect_history()
        else:
            history = self._collect_history()
        model = IsolationForest(n_estimators=250, contamination=0.05, max_samples="auto", random_state=42)
        model.fit(prepare_features(history[BASE_FEATURES]))
        joblib.dump(model, MODEL_FILE)
        return model

    def score_processes(self, processes=None):
        scored = []
        source = processes if processes is not None else psutil.process_iter()
        for proc in source:
            record = get_process_record(proc)
            if not record:
                continue
            frame = pd.DataFrame([{key: record[key] for key in BASE_FEATURES}])
            score = float(self.model.decision_function(prepare_features(frame))[0])
            prediction = int(self.model.predict(prepare_features(frame))[0])
            record["anomaly_score"] = score
            record["is_anomalous"] = prediction == -1 or score < 0.05
            scored.append(record)
        return scored

    @staticmethod
    def score_records(records):
        return records
