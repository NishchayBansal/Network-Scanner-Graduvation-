import socket
from tkinter import *
from tkinter import messagebox, ttk
import threading
from scapy.all import ARP, Ether, srp
from getmac import get_mac_address
import platform
import subprocess

# Function to scan the network and return list of live hosts
def scan_network(ip_range):
    live_hosts = []
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, received in result:
        live_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return live_hosts

# Port Scanner
def scan_ports(ip, ports=[20, 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Simple vulnerability check (demo purpose only)
def check_vulnerabilities(ports):
    vulns = {
        21: "FTP - Unencrypted login",
        23: "Telnet - Unencrypted and outdated",
        80: "HTTP - Use HTTPS instead",
        139: "NetBIOS - Can be vulnerable",
        445: "SMB - Target for ransomware"
    }
    return [vulns[p] for p in ports if p in vulns]

# Ping a host to check if it's alive
def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

# Clear Results
def clear_results():
    result_text.delete(1.0, END)

# Ping Selected IP
def ping_selected():
    ip = ip_range_entry.get()
    if not ip:
        messagebox.showerror("Error", "Please enter an IP address to ping.")
        return
    result_text.delete(1.0, END)
    result_text.insert(END, f"Pinging {ip}...\n")
    if ping_host(ip):
        result_text.insert(END, f"Host {ip} is reachable.\n")
    else:
        result_text.insert(END, f"Host {ip} is unreachable.\n")

# Threaded Scan Start
def start_scan():
    ip_range = ip_range_entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter IP Range.")
        return

    result_text.delete(1.0, END)
    result_text.insert(END, f"Scanning {ip_range}...\n")

    def scan():
        devices = scan_network(ip_range)
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            ports = scan_ports(ip)
            vulns = check_vulnerabilities(ports)

            result_text.insert(END, f"\nDevice Found:\nIP: {ip}\nMAC: {mac}\n")
            result_text.insert(END, f"Open Ports: {ports}\n")
            if vulns:
                result_text.insert(END, f"Potential Vulnerabilities:\n")
                for v in vulns:
                    result_text.insert(END, f" - {v}\n")
            else:
                result_text.insert(END, f"No common vulnerabilities detected.\n")
        result_text.insert(END, "\nScan Completed.")

    threading.Thread(target=scan).start()

# GUI Setup
app = Tk()
app.title("Python Network Scanner")
app.geometry("950x750")
app.configure(bg="#f0f2f5")
app.resizable(False, False)

frame = Frame(app, bg="#f0f2f5")
frame.pack(pady=20)

label = Label(frame, text="Enter IP Range (e.g. 192.168.1.1/24):", bg="#f0f2f5", font=('Arial', 12))
label.grid(row=0, column=0, padx=5, pady=5)

ip_range_entry = Entry(frame, width=30, font=('Arial', 12))
ip_range_entry.grid(row=0, column=1, padx=5, pady=5)

scan_button = Button(frame, text="Start Scan", command=start_scan, bg='green', fg='white', font=('Arial', 11))
scan_button.grid(row=0, column=2, padx=5, pady=5)

ping_button = Button(frame, text="Ping Host", command=ping_selected, bg='blue', fg='white', font=('Arial', 11))
ping_button.grid(row=1, column=1, pady=10)

clear_button = Button(frame, text="Clear Results", command=clear_results, bg='red', fg='white', font=('Arial', 11))
clear_button.grid(row=1, column=2, pady=10)

result_text = Text(app, wrap=WORD, width=110, height=30, font=('Courier New', 10))
result_text.pack(pady=10)

app.mainloop()
