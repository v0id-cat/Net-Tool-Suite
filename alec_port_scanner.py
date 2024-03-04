# CSEC 559 - AI Project 2
# Alec Miller + ChatGPT-generated code
import nmap
import argparse
import os
from prettytable import PrettyTable

# use pip to install python-nmap and prettytable

# scan a list of IP addresses using NMAP
def scan_ips(ips):
    table = PrettyTable(["IP Address", "Port", "Service"])
    nm = nmap.PortScanner()
    for ip in ips:
	# currently scanning all ports, smaller range would be more efficient
        nm.scan(hosts=ip, arguments='-p 1-65535 -T4') # Scan all ports
        for host in nm.all_hosts():
	    # Scan hosts, if they're accessible
            if nm[host].state() == 'up':
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
			# Identify service
                        service = nm[host][proto][port]['name']
                        table.add_row([host, port, service])
    # outputs table of IPs, ports, and services to terminal
    print(table)

# Parses either a file with IP addresses, a range, or a single IP
def parse_input(input_str):
    if os.path.isfile(input_str):
        with open(input_str, 'r') as file:
            return file.read().splitlines()
    elif '-' in input_str:
        start, end = input_str.split('-')
        start_int = int(start.split('.')[-1])
        end_int = int(end.split('.')[-1])
        ip_base = '.'.join(start.split('.')[:-1])
        ips = [f"{ip_base}.{i}" for i in range(start_int, end_int + 1)]
        return ips
    else:
        return [input_str]

# Main function and help menu
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IPs for open ports")
    parser.add_argument("input", help="IP address, IP range (e.g., 192.168.1.1-192.168.1.10), or file containing IPs")
    args = parser.parse_args()
    # get ip addresses to scan from input, and scan ports
    ips = parse_input(args.input)
    scan_ips(ips)
