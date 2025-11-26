#!/usr/bin/env python3
# scan.py 
import socket, json, argparse, concurrent.futures, datetime

COMMON_PORTS = [21,22,23,25,80,135,139,143,443,445,3306,3389,8080]

def tcp_connect_banner(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass
        data = b""
        try:
            data = s.recv(1024)
        except:
            pass
        s.close()
        return data.decode(errors="ignore").strip()
    except Exception as e:
        return None

def scan_host(ip, ports):
    results = {"ip": ip, "open_ports": []}
    for p in ports:
        banner = tcp_connect_banner(ip, p)
        if banner is not None and len(banner) > 0:
            results["open_ports"].append({"port": p, "banner": banner})
    return results

def simple_vuln_checks(scan_result):
    vulns = []
    for p in scan_result["open_ports"]:
        port = p["port"]; b = p["banner"].lower()
        if port == 23:
            vulns.append({"port":port, "issue":"Telnet open — insecure", "severity":"high"})
        if "apache" in b and "2.2" in b:
            vulns.append({"port":port, "issue":"Old Apache 2.2 detected", "severity":"medium"})
        if port == 21 and "anonymous" in b:
            vulns.append({"port":port, "issue":"Anonymous FTP", "severity":"high"})
    return vulns

def main(targets, ports, workers=8, out="report.json"):
    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_host, t, ports) for t in targets]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            res["vulns"] = simple_vuln_checks(res)
            all_results.append(res)

    report = {
        "generated": datetime.datetime.utcnow().isoformat()+"Z",
        "summary": {"hosts_scanned": len(targets)},
        "results": all_results
    }
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"Wrote {out} — hosts: {len(targets)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", help="IP(s) to scan (use only lab IPs)")
    parser.add_argument("--ports", nargs="*", type=int, default=COMMON_PORTS)
    parser.add_argument("--out", default="report.json")
    args = parser.parse_args()
    main(args.targets, args.ports, workers=16, out=args.out)
