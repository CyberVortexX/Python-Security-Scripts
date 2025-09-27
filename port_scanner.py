# port_scanner.py
import socket
import sys
from datetime import datetime

def scan_port(host, port):
    """Attempts to connect to a specific port on a host."""
    try:
        # Create a socket object (AF_INET for IPv4, SOCK_STREAM for TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1) # Set a timeout of 1 second

        # Attempt to connect
        result = s.connect_ex((host, port))

        if result == 0:
            return True # Port is open
        else:
            return False # Port is closed/filtered
    except Exception as e:
        # Handle exceptions like 'host not found'
        return False
    finally:
        s.close()

def main():
    """Main function to run the port scanner."""
    print("--- Basic Network Port Scanner ---")
    
    # Get target host from user
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = input("Enter the target IP address or hostname: ")
        
    # Standard ports to check (HTTP, HTTPS, SSH, FTP, etc.)
    ports_to_check = [21, 22, 23, 25, 80, 443, 3389, 8080]

    try:
        # Resolve hostname to IP address
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n❌ Error: Hostname '{target}' could not be resolved.")
        sys.exit()

    print(f"\nScanning Target: {target_ip}")
    print("-" * 40)
    
    start_time = datetime.now()

    for port in ports_to_check:
        if scan_port(target_ip, port):
            print(f"✅ Port {port:<5} is OPEN")

    print("-" * 40)
    end_time = datetime.now()
    total_time = end_time - start_time
    print(f"Scan finished in: {total_time}")

if __name__ == "__main__":
    main()
