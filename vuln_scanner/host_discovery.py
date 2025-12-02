from __future__ import annotations
import subprocess
import ipaddress
import socket
import sys
from typing import List

def ping_sweep_nmap(ip_range: str) -> List[str]:
    """
    Run 'nmap -sn <ip_range> -oX -' and parse IPv4 addresses from XML output.
    Returns a list of discovered IP strings. If nmap is not installed or fails,
    returns an empty list.
    """
    command = ["nmap", "-sn", ip_range, "-oX", "-"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        # nmap binary not found
        print("[host_discovery] nmap not found on PATH. Install nmap or use ping_sweep_tcp.", file=sys.stderr)
        return []

    if result.returncode != 0:
        # nmap ran but returned an error
        stderr = result.stderr.strip()
        print(f"[host_discovery] nmap error: {stderr}", file=sys.stderr)
        return []

    hosts: List[str] = []
    for line in result.stdout.splitlines():
        # look for lines like: <address addr="192.168.1.10" addrtype="ipv4"/>
        if "<address addr=\"" in line and "addrtype=\"ipv4\"" in line:
            try:
                ip = line.split('addr="')[1].split('"')[0]
                hosts.append(ip)
            except Exception:
                continue
    return hosts

def ping_sweep_tcp(ip_range: str, probe_ports: List[int] = [80], timeout: float = 0.6, max_hosts: int = 1024) -> List[str]:
    """
    Fallback discovery using TCP connect probes.
    - ip_range: single IP (e.g., "192.168.1.10") or CIDR (e.g., "192.168.1.0/24")
    - probe_ports: list of integer ports to try (default [80])
    - timeout: socket connect/read timeout in seconds
    - max_hosts: safety cap on number of hosts to iterate (prevents accidental /8 scans)
    Returns: list of live IP strings.
    """
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        # If parsing fails, maybe it's a single IP without CIDR; try to handle that.
        try:
            ip = ipaddress.ip_address(ip_range)
            net = ipaddress.ip_network(f"{ip}/32", strict=False)
        except ValueError:
            print(f"[host_discovery] Invalid IP or network: {ip_range}", file=sys.stderr)
            return []

    all_hosts = list(net.hosts())
    if len(all_hosts) > max_hosts:
        print(f"[host_discovery] Refusing to iterate {len(all_hosts)} hosts (max {max_hosts}). Reduce range or raise max_hosts.", file=sys.stderr)
        return []

    live_hosts: List[str] = []
    for ip in all_hosts:
        ip_str = str(ip)
        is_alive = False
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((ip_str, port))
                    # If connect succeeds, we consider host alive
                    is_alive = True
                    break
            except Exception:
                # connect failed -> try next port
                continue
        if is_alive:
            live_hosts.append(ip_str)
    return live_hosts

# Convenience wrapper used by scan.py (choose strategy)
def ping_sweep(ip_range: str, prefer_nmap: bool = True) -> List[str]:
    """
    Convenience function called by scan.py.
    If prefer_nmap=True, attempt nmap first; if that fails, fall back to TCP probes.
    """
    if prefer_nmap:
        hosts = ping_sweep_nmap(ip_range)
        if hosts:
            return hosts
        # fall back if nmap not present or returned nothing
    # default fallback probe ports include 80 and 443 (more likely to be up)
    return ping_sweep_tcp(ip_range, probe_ports=[80, 443], timeout=0.6, max_hosts=1024)

if __name__ == "__main__":
    # quick CLI test: python host_discovery.py 127.0.0.1/32
    import argparse
    parser = argparse.ArgumentParser(description="Host discovery helper (nmap or TCP fallback)")
    parser.add_argument("range", help="IP or network (e.g., 127.0.0.1/32 or 192.168.1.0/24)")
    parser.add_argument("--no-nmap", action="store_true", help="Do not attempt nmap; use TCP fallback")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Max hosts to iterate for TCP fallback")
    args = parser.parse_args()

    if args.no_nmap:
        found = ping_sweep_tcp(args.range, probe_ports=[80,443], max_hosts=args.max_hosts)
    else:
        found = ping_sweep(args.range)
    print("Live hosts:", found)
