import tkinter as tk
from tkinter import ttk

# Import functionalities from part1.py
import subprocess
import socket
import whois
import geoip2.database
import nmap
from prettytable import PrettyTable
import argparse

# from part1 import scan_network, reverse_ip_lookup, port_scan

class NetworkToolGUI(tk.Tk):
	def __init__(self):
		super().__init__()
		self.title("Network Tool GUI")
		self.geometry("800x600")

		# Tab Control Setup
		tab_control = ttk.Notebook(self)

		# Network Mapper Tab Setup
		self.network_mapper_tab = ttk.Frame(tab_control)
		tab_control.add(self.network_mapper_tab, text='Network Mapper')
		self.setup_network_mapper_tab()

		# Reverse IP Lookup Tab Setup
		self.reverse_ip_lookup_tab = ttk.Frame(tab_control)
		tab_control.add(self.reverse_ip_lookup_tab, text='Reverse IP Lookup')
		self.setup_reverse_ip_lookup_tab()

		# Port Scanner Tab Setup
		self.port_scanner_tab = ttk.Frame(tab_control)
		tab_control.add(self.port_scanner_tab, text='Port Scanner')
		self.setup_port_scanner_tab()

		tab_control.pack(expand=1, fill="both")

	def setup_network_mapper_tab(self):
		ttk.Label(self.network_mapper_tab, text="Subnet:").grid(row=0, column=0, padx=10, pady=10)
		subnet_entry = ttk.Entry(self.network_mapper_tab)
		subnet_entry.grid(row=0, column=1, padx=10, pady=10)
		scan_button = ttk.Button(self.network_mapper_tab, text="Scan", command=lambda: self.scan_network(subnet_entry.get()))
		scan_button.grid(row=0, column=2, padx=10, pady=10)
		self.network_scan_output = tk.Text(self.network_mapper_tab, height=10, width=50)
		self.network_scan_output.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

	def setup_reverse_ip_lookup_tab(self):
		ttk.Label(self.reverse_ip_lookup_tab, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
		ip_entry = ttk.Entry(self.reverse_ip_lookup_tab)
		ip_entry.grid(row=0, column=1, padx=10, pady=10)
		lookup_button = ttk.Button(self.reverse_ip_lookup_tab, text="Lookup", command=lambda: self.reverse_ip_lookup(ip_entry.get()))
		lookup_button.grid(row=0, column=2, padx=10, pady=10)
		self.reverse_ip_lookup_output = tk.Text(self.reverse_ip_lookup_tab, height=10, width=50)
		self.reverse_ip_lookup_output.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

	def setup_port_scanner_tab(self):
		ttk.Label(self.port_scanner_tab, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
		ip_entry = ttk.Entry(self.port_scanner_tab)
		ip_entry.grid(row=0, column=1, padx=10, pady=10)
		scan_button = ttk.Button(self.port_scanner_tab, text="Scan Ports", command=lambda: self.port_scan(ip_entry.get()))
		scan_button.grid(row=0, column=2, padx=10, pady=10)
		self.port_scan_output = tk.Text(self.port_scanner_tab, height=10, width=50)
		self.port_scan_output.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

	# Replace these methods with actual calls to functions from part1.py
	def scan_network(self, subnet):
		devices = []
		for i in range(1, 256):
			ip = f"{subnet}.{i}"
			try:
				result = subprocess.check_output(["sudo", "nmap", "-sn", ip], stderr=subprocess.STDOUT)
				if "Host is up" in result.decode('utf-8'):
					devices.append(ip)
			except subprocess.CalledProcessError as e:
				print(f"Scan error on {ip}: {e}")
		return devices

	def reverse_ip_lookup(self, ip):
		try:
			domain = socket.gethostbyaddr(ip)[0]
			domain_info = whois.whois(domain)
			registrant = domain_info.registrant_name if domain_info.registrant_name else "Unknown"

			# Using geoip2 to find the location of the IP
			with geoip2.database.Reader('GeoLite2-City_20240223/GeoLite2-City.mmdb') as reader:  # Update the path to the GeoLite2-City database
				response = reader.city(ip)
				location = f"{response.city.name}, {response.country.name}"
		except Exception as e:
			print(f"Error during reverse IP lookup for {ip}: {e}")
			domain, registrant, location = "Error", "Error", "Error"
		return domain, registrant, location

	def port_scan(self, ip):
		nm = nmap.PortScanner()
		scan_results = PrettyTable(["IP Address", "Port", "Service"])
		#for ip in ip_range:
		# removing range capability for now
		nm.scan(hosts=ip, arguments='-p 1-65535 -T4')  # Adjust the port range and arguments as needed
		for host in nm.all_hosts():
			if nm[host].state() == 'up':
				for proto in nm[host].all_protocols():
					lport = nm[host][proto].keys()
					for port in lport:
						service = nm[host][proto][port]['name']
						scan_results.add_row([ip, port, service])

def main():
	app = NetworkToolGUI()
	app.mainloop()

if __name__ == "__main__":
	main()
