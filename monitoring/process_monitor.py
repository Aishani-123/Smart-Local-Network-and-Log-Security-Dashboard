import psutil
import time


def get_processes():

    processes = []

    # First CPU measurement
    for process in psutil.process_iter(
        ['pid', 'name', 'memory_percent']
    ):
        try:
            process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Wait for measurement interval
    time.sleep(1)

    # Second CPU measurement
    for process in psutil.process_iter(
        ['pid', 'name', 'memory_percent']
    ):
        try:
            cpu_usage = process.cpu_percent(interval=None)
            info = process.info

            processes.append({
                "pid": info["pid"],
                "process_name": info["name"],
                "cpu_usage": cpu_usage,
                "memory_usage": info["memory_percent"]
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


if __name__ == "__main__":
    data = get_processes()

    for process in data:
        print(process)