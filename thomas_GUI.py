
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import nmap
import socket
import whois
import geoip2.database
from prettytable import PrettyTable

# Function to perform network scan
def scan_network(ip_prefix, output_widget):
    devices = [f"{ip_prefix}.{i}" for i in range(1, 256)]  # Generate IP addresses
    nm = nmap.PortScanner()
    for ip in devices:
        try:
            nm.scan(hosts=ip, arguments='-sP')  # Ping scan to check if the host is up
            if nm.all_hosts():  # If host is up, display it in the output widget
                output_widget.insert(tk.END, f"Host: {ip} is up\n")
        except Exception as e:
            output_widget.insert(tk.END, f"Error scanning {ip}: {e}\n")

# Function to perform DNS lookup
def dns_lookup(hostname, output_widget):
    try:
        ip_address = socket.gethostbyname(hostname)
        output_widget.insert(tk.END, f"Hostname: {hostname}, IP: {ip_address}\n")
    except socket.error as err:
        output_widget.insert(tk.END, f"DNS lookup failed for {hostname}: {err}\n")

# Function to perform WHOIS lookup
def whois_lookup(domain, output_widget):
    try:
        domain_info = whois.whois(domain)
        output_widget.insert(tk.END, str(domain_info) + "\n")
    except Exception as e:
        output_widget.insert(tk.END, f"WHOIS lookup failed for {domain}: {e}\n")

# Function to perform GeoIP lookup
def geoip_lookup(ip_address, output_widget):
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:  # Update the path to your GeoLite2 database
            response = reader.city(ip_address)
            output_widget.insert(tk.END, f"IP: {ip_address}, Country: {response.country.name}, City: {response.city.name}\n")
    except Exception as e:
        output_widget.insert(tk.END, f"GeoIP lookup failed for {ip_address}: {e}\n")

# Define threading functions for each operation to keep the GUI responsive
def threaded_network_scan(ip_prefix, output_widget):
    threading.Thread(target=scan_network, args=(ip_prefix, output_widget,)).start()

def threaded_dns_lookup(hostname, output_widget):
    threading.Thread(target=dns_lookup, args=(hostname, output_widget,)).start()

def threaded_whois_lookup(domain, output_widget):
    threading.Thread(target=whois_lookup, args=(domain, output_widget,)).start()

def threaded_geoip_lookup(ip_address, output_widget):
    threading.Thread(target=geoip_lookup, args=(ip_address, output_widget,)).start()

# Main application class
class NetworkToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Tool")
        self.geometry("800x600")

        # Create tabs
        self.tab_control = ttk.Notebook(self)
        self.tab_network_scan = ttk.Frame(self.tab_control)
        self.tab_dns_lookup = ttk.Frame(self.tab_control)
        self.tab_whois_lookup = ttk.Frame(self.tab_control)
        self.tab_geoip_lookup = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_network_scan, text='Network Scan')
        self.tab_control.add(self.tab_dns_lookup, text='DNS Lookup')
        self.tab_control.add(self.tab_whois_lookup, text='WHOIS Lookup')
        self.tab_control.add(self.tab_geoip_lookup, text='GeoIP Lookup')
        self.tab_control.pack(expand=1, fill="both")

        # Initialize UI components for each tab
        self.init_network_scan_ui()
        self.init_dns_lookup_ui()
        self.init_whois_lookup_ui()
        self.init_geoip_lookup_ui()

    def init_network_scan_ui(self):
        # Components for Network Scan tab
        label = ttk.Label(self.tab_network_scan, text="IP Prefix (e.g., 192.168.1):")
        label.pack(pady=10)
        self.entry_ip_prefix = ttk.Entry(self.tab_network_scan)
        self.entry_ip_prefix.pack(pady=10)
        scan_button = ttk.Button(self.tab_network_scan, text="Scan", command=self.perform_network_scan)
        scan_button.pack(pady=10)
        self.text_network_scan_result = scrolledtext.ScrolledText(self.tab_network_scan, width=70, height=15)
        self.text_network_scan_result.pack(pady=10)

    def init_dns_lookup_ui(self):
        # Components for DNS Lookup tab
        label = ttk.Label(self.tab_dns_lookup, text="Hostname:")
        label.pack(pady=10)
        self.entry_hostname = ttk.Entry(self.tab_dns_lookup)
        self.entry_hostname.pack(pady=10)
        lookup_button = ttk.Button(self.tab_dns_lookup, text="Lookup", command=self.perform_dns_lookup)
        lookup_button.pack(pady=10)
        self.text_dns_lookup_result = scrolledtext.ScrolledText(self.tab_dns_lookup, width=70, height=15)
        self.text_dns_lookup_result.pack(pady=10)

    def init_whois_lookup_ui(self):
        # Components for WHOIS Lookup tab
        label = ttk.Label(self.tab_whois_lookup, text="Domain:")
        label.pack(pady=10)
        self.entry_domain = ttk.Entry(self.tab_whois_lookup)
        self.entry_domain.pack(pady=10)
        lookup_button = ttk.Button(self.tab_whois_lookup, text="Lookup", command=self.perform_whois_lookup)
        lookup_button.pack(pady=10)
        self.text_whois_lookup_result = scrolledtext.ScrolledText(self.tab_whois_lookup, width=70, height=15)
        self.text_whois_lookup_result.pack(pady=10)

    def init_geoip_lookup_ui(self):
        # Components for GeoIP Lookup tab
        label = ttk.Label(self.tab_geoip_lookup, text="IP Address:")
        label.pack(pady=10)
        self.entry_ip_address = ttk.Entry(self.tab_geoip_lookup)
        self.entry_ip_address.pack(pady=10)
        lookup_button = ttk.Button(self.tab_geoip_lookup, text="Lookup", command=self.perform_geoip_lookup)
        lookup_button.pack(pady=10)
        self.text_geoip_lookup_result = scrolledtext.ScrolledText(self.tab_geoip_lookup, width=70, height=15)
        self.text_geoip_lookup_result.pack(pady=10)

    # Functions to initiate threaded operations
    def perform_network_scan(self):
        ip_prefix = self.entry_ip_prefix.get()
        threaded_network_scan(ip_prefix, self.text_network_scan_result)

    def perform_dns_lookup(self):
        hostname = self.entry_hostname.get()
        threaded_dns_lookup(hostname, self.text_dns_lookup_result)

    def perform_whois_lookup(self):
        domain = self.entry_domain.get()
        threaded_whois_lookup(domain, self.text_whois_lookup_result)

    def perform_geoip_lookup(self):
        ip_address = self.entry_ip_address.get()
        threaded_geoip_lookup(ip_address, self.text_geoip_lookup_result)

# Running the application
if __name__ == "__main__":
    app = NetworkToolApp()
    app.mainloop()
