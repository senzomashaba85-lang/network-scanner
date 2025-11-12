import ipaddress
import subprocess
import platform
import concurrent.futures
import socket

def ping(ip):
    """Ping a single IP address and return it if alive."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "200", str(ip)]  # 200ms timeout
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return ip if output.returncode == 0 else None
    except Exception:
        return None

def scan_network(network):
    """Scan a subnet and return list of active hosts."""
    active_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping, ip) for ip in ipaddress.IPv4Network(network)]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                active_hosts.append(str(result))
    return active_hosts

def scan_ports(ip, ports=None):
    """Scan ports on a given IP address."""
    if ports is None:
        ports = [22, 80, 443, 502]  # SSH, HTTP, HTTPS, Modbus/TCP
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports
