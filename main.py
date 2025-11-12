from src.scanner import scan_network, scan_ports

if __name__ == "__main__":
    subnet = "192.168.0.0/24"   # adjust to your work subnet
    hosts = scan_network(subnet)
    print("Active hosts and open ports:")
    for h in hosts:
        ports = scan_ports(h)
        print(f"{h} -> Open ports: {ports if ports else 'None'}")
