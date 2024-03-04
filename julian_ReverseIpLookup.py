import csv
import socket
import whois
import geoip2.database
from multiprocessing import Pool
from tqdm import tqdm

def get_domain_name(ip):
    try:
        domain_name = socket.gethostbyaddr(ip)[0]
        return domain_name
    except socket.herror:
        return "No Domain Found"

def get_registrant_name(domain):
    try:
        domain_info = whois.whois(domain)
        registrant_name = domain_info.registrant_name
        return registrant_name
    except (AttributeError, KeyError):
        return "No Registrant Name Found"

def get_location(ip):
    try:
        reader = geoip2.database.Reader(r'C:\Users\Owner\Downloads\GeoLite2-City_20240223\GeoLite2-City_20240223\GeoLite2-City.mmdb')
        response = reader.city(ip)
        city = response.city.name
        country = response.country.iso_code
        location = f"{city}, {country}" if city else country
        reader.close()
        return location
    except geoip2.errors.AddressNotFoundError:
        return "Unknown Location"
    except Exception as e:
        print(f"Error retrieving location for IP {ip}: {e}")
        return "Unknown Location"

def process_ip(ip):
    ip = ip.strip()
    domain = get_domain_name(ip)
    registrant_name = get_registrant_name(domain)
    location = get_location(ip)
    return (ip, domain, registrant_name, location)

def print_progress(current, total):
    progress = (current / total) * 100
    print(f"Progress: {current}/{total} ({progress:.2f}%)", end="\r")

def main():
    filename = input("Enter the path to the file containing IP addresses: ")
    try:
        with open(filename, 'r') as file:
            ips = file.readlines()
    except FileNotFoundError:
        print("File not found.")
        return

    print("Performing reverse DNS lookups, IP geolocation, and retrieving ASN...")

    total_ips = len(ips)
    ip_info = []
    with Pool() as pool, tqdm(total=total_ips) as pbar:
        for result in pool.imap_unordered(process_ip, ips):
            ip_info.append(result)
            pbar.update(1)
            print_progress(len(ip_info), total_ips)

    output_filename = "ip_info.csv"
    with open(output_filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Domain', 'Registrant Name', 'Location'])
        for ip, domain, registrant_name, location in ip_info:
            writer.writerow([ip, domain, registrant_name, location])

    print(f"\nResults saved to {output_filename}")

if __name__ == "__main__":
    main()
