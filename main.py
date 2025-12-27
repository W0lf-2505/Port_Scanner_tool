
import socket
import sys

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443]

def scan_ports(target):
    print(f"[+] Starting port scan on {target}")
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} open")
            s.close()
        except:
            pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    scan_ports(target_ip)
