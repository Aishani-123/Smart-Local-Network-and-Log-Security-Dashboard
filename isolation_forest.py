import os
import time
from pathlib import Path
from functools import lru_cache
import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
history_file = str(DATA_DIR / "real_historical_process_records.csv")
model_file = str(DATA_DIR / "real_process_anomaly_model.pkl")
result_file = str(DATA_DIR / "latest_process_score.csv")

base_features = ["process_size_mb", "memory_usage_mb", "cpu_usage", "execution_time_sec",
                 "thread_count", "network_connections", "bytes_sent_mb", "failed_accesses",
                 "file_operations"]


def prepare_features(data):
    data = data.copy()
    data["memory_size_ratio"] = data["memory_usage_mb"] / data["process_size_mb"].clip(lower=0.1)
    data["time_size_ratio"] = data["execution_time_sec"] / data["process_size_mb"].clip(lower=0.1)
    data["network_per_thread"] = data["network_connections"] / data["thread_count"].clip(lower=1)
    data["data_per_connection"] = data["bytes_sent_mb"] / data["network_connections"].clip(lower=1)
    return data.replace([np.inf, -np.inf], np.nan).fillna(0)


@lru_cache(maxsize=1024)
def _executable_size(executable):
    try:
        return os.path.getsize(executable) / (1024 * 1024) if executable and os.path.isfile(executable) else 0.1
    except OSError:
        return 0.1


def get_process_record(proc, cpu_interval=None, network_count=None):
    try:
        with proc.oneshot():
            pid = proc.pid
            memory = proc.memory_info().rss / (1024 * 1024)
            cpu = proc.cpu_percent(interval=cpu_interval)
            threads = proc.num_threads()
            age = max(0, time.time() - proc.create_time())
            try:
                exe = proc.exe()
                size = _executable_size(exe)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                size = 0.1
            if network_count is None:
                try:
                    connections = len(proc.net_connections(kind="inet"))
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    connections = 0
            else:
                connections = int(network_count)
        return {"pid": pid, "process_name": proc.name(), "process_size_mb": max(size, 0.1),
                "memory_usage_mb": memory, "cpu_usage": cpu, "execution_time_sec": age,
                "thread_count": max(threads, 1), "network_connections": connections,
                "bytes_sent_mb": 0.0, "failed_accesses": 0, "file_operations": 0}
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None


def collect_real_history(samples=5, sample_interval=2):
    records = []
    for sample in range(samples):
        for proc in psutil.process_iter():
            record = get_process_record(proc)
            if record is not None:
                records.append(record)
        if sample < samples - 1:
            time.sleep(sample_interval)
    if len(records) < 10:
        raise RuntimeError("Not enough process data was collected. Try again.")
    history = pd.DataFrame(records)
    history = history[base_features].replace([np.inf, -np.inf], np.nan).dropna()
    history = history[history["process_size_mb"] > 0]
    if len(history) < 10:
        raise RuntimeError("Not enough valid process records were collected to train the model.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    history.to_csv(history_file, index=False)
    return history


def get_history(force_retrain=False):
    if not force_retrain and os.path.exists(history_file):
        try:
            history = pd.read_csv(history_file)
            if all(column in history.columns for column in base_features):
                history = history[base_features].replace([np.inf, -np.inf], np.nan).dropna()
                if len(history) >= 10:
                    return history
        except (OSError, ValueError, pd.errors.ParserError):
            pass
    return collect_real_history()


def load_or_train_model(force_retrain=False):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not force_retrain and os.path.exists(model_file):
        try:
            model = joblib.load(model_file)
            if getattr(model, "n_features_in_", None) == len(base_features) + 4:
                return model
        except (OSError, ValueError, EOFError, AttributeError):
            pass
    history = get_history(force_retrain=force_retrain)
    X_history = prepare_features(history[base_features])
    model = IsolationForest(n_estimators=250, contamination=0.05,
                            max_samples="auto", random_state=42)
    model.fit(X_history)
    joblib.dump(model, model_file)
    return model


def score_processes(model, cpu_by_pid=None, network_counts=None):
    cpu_by_pid = cpu_by_pid or {}
    network_counts = network_counts or {}
    results = []
    for proc in psutil.process_iter():
        try:
            pid = proc.pid
            record = get_process_record(proc, network_count=network_counts.get(pid, 0))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if record is None:
            continue
        record["cpu_usage"] = cpu_by_pid.get(record["pid"], record["cpu_usage"])
        results.append(record)
    if not results:
        return results
    rows = pd.DataFrame([{feature: record[feature] for feature in base_features} for record in results])
    scores = model.decision_function(prepare_features(rows))
    for record, score in zip(results, scores):
        record["anomaly_score"] = float(score)
        # Preserve the supplied script's score < 0.05 unusual-process threshold.
        record["is_anomalous"] = record["anomaly_score"] < 0.05
    return results


def analyze_pid(pid, model=None):
    model = model or load_or_train_model()
    proc = psutil.Process(int(pid))
    record = get_process_record(proc, cpu_interval=1)
    if record is None:
        raise RuntimeError("Could not access this process; it may have closed or access may be denied.")
    row = pd.DataFrame([record])
    record["anomaly_score"] = float(model.decision_function(prepare_features(row[base_features]))[0])
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([record])[ ["pid"] + base_features + ["anomaly_score"] ].to_csv(result_file, index=False)
    return record


if __name__ == "__main__":
    try:
        trained_model = load_or_train_model()
        process_id = int(input("Enter the process ID (PID) to analyse: "))
        result = analyze_pid(process_id, trained_model)
        print("Anomaly score:", round(result["anomaly_score"], 6))
        if result["anomaly_score"] < 0:
            print("The process is unusual compared with the training data.")
        else:
            print("The process is not identified as unusual by the model.")
        print("Result saved to", result_file)
    except (RuntimeError, OSError, ValueError, psutil.Error) as error:
        print("Could not analyse the process:", error)
