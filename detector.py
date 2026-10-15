import os
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HISTORY_FILE = DATA_DIR / "process_history.csv"
MODEL_FILE = DATA_DIR / "process_anomaly_model.pkl"
BASE_FEATURES = ["process_size_mb", "memory_usage_mb", "cpu_usage", "execution_time_sec",
                 "thread_count", "network_connections", "bytes_sent_mb", "failed_accesses", "file_operations"]


def prepare_features(data):
    data = data.copy()
    size = data.process_size_mb.clip(lower=0.1)
    data["memory_size_ratio"] = data.memory_usage_mb / size
    data["time_size_ratio"] = data.execution_time_sec / size
    data["network_per_thread"] = data.network_connections / data.thread_count.clip(lower=1)
    data["data_per_connection"] = data.bytes_sent_mb / data.network_connections.clip(lower=1)
    return data.replace([np.inf, -np.inf], np.nan).fillna(0)


def get_process_record(proc):
    try:
        with proc.oneshot():
            exe = proc.exe()
            try:
                size = os.path.getsize(exe) / 1048576 if exe and os.path.isfile(exe) else 0.1
            except OSError:
                size = 0.1
            try:
                sockets = len(proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                sockets = 0
            return {"pid": proc.pid, "process_name": proc.name(), "process_size_mb": max(size, 0.1),
                    "memory_usage_mb": proc.memory_info().rss / 1048576, "cpu_usage": proc.cpu_percent(None),
                    "execution_time_sec": max(0, time.time() - proc.create_time()),
                    "thread_count": max(proc.num_threads(), 1), "network_connections": sockets,
                    "bytes_sent_mb": 0.0, "failed_accesses": 0, "file_operations": 0}
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None


class ProcessAnomalyDetector:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.model = self._load_or_train()

    def _collect_history(self):
        rows = [r for p in psutil.process_iter() if (r := get_process_record(p))]
        frame = pd.DataFrame(rows)
        if frame.empty:
            raise RuntimeError("No processes were accessible for model training.")
        frame = frame[BASE_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
        if frame.empty:
            raise RuntimeError("No valid process records were available for model training.")
        if len(frame) < 10:
            frame = pd.concat([frame] * ((10 + len(frame) - 1) // len(frame)), ignore_index=True)
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
        try:
            history = pd.read_csv(HISTORY_FILE)
            if len(history) < 10 or not set(BASE_FEATURES).issubset(history.columns):
                raise ValueError("Saved process baseline is incomplete")
            history = history[BASE_FEATURES].replace([np.inf, -np.inf], np.nan).dropna()
        except (OSError, ValueError, pd.errors.ParserError):
            history = self._collect_history()
        model = IsolationForest(n_estimators=250, contamination=0.05, max_samples="auto", random_state=42)
        model.fit(prepare_features(history[BASE_FEATURES]))
        joblib.dump(model, MODEL_FILE)
        return model

    def retrain(self):
        history = self._collect_history()
        self.model = IsolationForest(n_estimators=250, contamination=0.05, max_samples="auto", random_state=42)
        self.model.fit(prepare_features(history[BASE_FEATURES]))
        joblib.dump(self.model, MODEL_FILE)

    def score_processes(self):
        records = [r for p in psutil.process_iter() if (r := get_process_record(p))]
        if not records:
            return []
        frame = pd.DataFrame([{k: r[k] for k in BASE_FEATURES} for r in records])
        features = prepare_features(frame)
        scores = self.model.decision_function(features)
        predictions = self.model.predict(features)
        for record, score, prediction in zip(records, scores, predictions):
            record["anomaly_score"] = float(score)
            record["model_flag"] = bool(prediction == -1)
        return records
