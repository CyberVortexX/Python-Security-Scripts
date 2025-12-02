import subprocess

def ping_sweep(ip_range):
    """
    Runs 'nmap -sn' on an IP range.
    Returns a list of live hosts.
    """

    command = ["nmap", "-sn", ip_range, "-oX", "-"]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error running nmap. Make sure it is installed.")
        return []

    hosts = []
    for line in result.stdout.splitlines():
        # XML output: <address addr="192.168.1.10" addrtype="ipv4"/>
        if "<address addr=\"" in line and "ipv4" in line:
            ip = line.split('addr="')[1].split('"')[0]
            hosts.append(ip)

    return hosts
