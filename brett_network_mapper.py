import subprocess
from prettytable import PrettyTable

def scan_network(ip):
    # Generate a list of IP addresses in the 192.168.1.x subnet
    devices = []
    for i in range(1, 256):
        target_ip = f"{ip}.{i}"
        devices.append(target_ip)

    return devices

def get_os_info(ip):
    # Use nmap to get operating system information
    try:
        result = subprocess.check_output(["sudo", "nmap", "-O", ip], timeout=10, universal_newlines=True)
        return result
    except subprocess.CalledProcessError:
        return "Unable to determine OS"

def print_table(devices):
    # Print the table with discovered devices and OS information
    table = PrettyTable(['IP Address', 'Operating System'])
    for device in devices:
        os_info = get_os_info(device)
        table.add_row([device, os_info.strip()])
    print(table)

if __name__ == "__main__":
    # Specify the fixed target IP address
    target_ip = "192.168.1"

    # Perform network scan
    devices = scan_network(target_ip)

    # Print the table with OS information
    print_table(devices)
