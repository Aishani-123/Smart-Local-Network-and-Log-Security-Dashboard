import psutil
from datetime import datetime, timezone

def get_process_name(pid):
    if pid is None:
        return None

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_network_connections():
    connections = []

    for conn in psutil.net_connections(kind="inet"):
        pid = conn.pid
        process_name = get_process_name(pid)

        source_ip = conn.laddr.ip if conn.laddr else None
        source_port = conn.laddr.port if conn.laddr else None

        destination_ip = conn.raddr.ip if conn.raddr else None
        destination_port = conn.raddr.port if conn.raddr else None

        connections.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pid": pid,
            "process_name": process_name,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "status": conn.status
        })

    return connections

if __name__ == "__main__":

    data = get_network_connections()

    for connection in data:
        print(connection)