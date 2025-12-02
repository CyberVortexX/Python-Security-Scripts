#!/usr/bin/env python3
# scan.py — Improved vuln scanner 
import socket
import json
import argparse
import concurrent.futures
import datetime
import re
from host_discovery import ping_sweep

COMMON_PORTS = [21,22,23,25,80,135,139,143,443,445,3306,3389,8080]

def tcp_connect_banner(ip, port, timeout=2, recv_size=4096):
    """
    Connects to ip:port. Returns (open_flag:bool, banner:str).
    open_flag = True when TCP connect succeeded (even if no banner).
    banner = decoded string (may be empty).
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Try to prompt a response for common protocols (non-fatal if fails)
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except Exception:
            pass

        data = b""
        try:
            while True:
                chunk = s.recv(recv_size)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data or len(data) > 8192:
                    break
        except socket.timeout:
            # okay — we collected what we could
            pass
        except Exception:
            pass

        try:
            s.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass

        return True, data.decode(errors="ignore").strip()
    except Exception:
        if s:
            try:
                s.close()
            except Exception:
                pass
        return False, ""

def scan_host(ip, ports):
    """
    Scan one host: attempt TCP connect on each port, capture banner if any.
    Returns dict: { ip, open_ports: [ {port, banner} ] }
    """
    results = {"ip": ip, "open_ports": []}
    for p in ports:
        open_flag, banner = tcp_connect_banner(ip, p)
        if open_flag:
            results["open_ports"].append({"port": p, "banner": banner})
    return results

def simple_vuln_checks(scan_result):
    """
    Rule-engine: examine banners and open-ports and return vuln list.
    """
    vulns = []
    for p in scan_result.get("open_ports", []):
        port = p["port"]
        b = (p.get("banner") or "").lower()

        # Direct port-based flags
        if port == 23:
            vulns.append({"port": port, "issue": "Telnet open — insecure", "severity": "high"})
        if port == 21 and "anonymous" in b:
            vulns.append({"port": port, "issue": "Anonymous FTP enabled", "severity": "high"})

        # HTTP Server header parsing
        m = re.search(r"server:\s*([^\r\n]+)", b, re.I)
        if m:
            server_line = m.group(1).strip()
            if "simplehttp" in server_line or "python" in server_line:
                vulns.append({"port": port, "issue": f"Dev/simple HTTP server detected: {server_line}", "severity": "low"})
            if "apache" in server_line and "2.2" in server_line:
                vulns.append({"port": port, "issue": f"Old Apache detected: {server_line}", "severity": "medium"})

        # If port open but no banner captured, flag for follow-up
        if b == "":
            vulns.append({"port": port, "issue": "Open port but no banner captured", "severity": "info"})

    return vulns

def build_report(all_results, out_path, targets_count):
    report = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {"hosts_scanned": targets_count},
        "results": all_results
    }
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Wrote {out_path} — hosts: {targets_count}")

def main(targets, ports, workers=8, out="report.json"):
    if not targets:
        print("No targets to scan.")
        return

    print(f"[+] Scanning targets: {targets} on ports: {ports} with {workers} workers")
    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_host, t, ports) for t in targets]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            res["vulns"] = simple_vuln_checks(res)
            all_results.append(res)

    build_report(all_results, out, len(targets))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vuln_scanner — lab use only")
    parser.add_argument("targets", nargs="*", help="IP(s) to scan (optional if --ping used)")
    parser.add_argument("--ping", help="IP range for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", nargs="*", type=int, default=COMMON_PORTS, help="Space-separated ports to scan")
    parser.add_argument("--out", default="report.json", help="Output JSON file")
    parser.add_argument("--workers", type=int, default=16, help="Thread pool size")
    args = parser.parse_args()

    targets = args.targets or []
    if args.ping:
        print(f"[+] Running host discovery on {args.ping} ...")
        discovered = ping_sweep(args.ping)
        print(f"[+] Live hosts found: {discovered}")
        targets = discovered

    if not targets:
        print("No targets provided or discovered. Use targets or --ping.")
        exit(1)

    main(targets, args.ports, workers=args.workers, out=args.out)
