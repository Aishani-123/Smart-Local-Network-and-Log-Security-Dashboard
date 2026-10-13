import psutil


def get_system_metrics():
    cpu_usage = psutil.cpu_percent(interval=1)

    memory = psutil.virtual_memory()

    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory.percent
    }


if __name__ == "__main__":
    data = get_system_metrics()
    print(data)