# Network-Scanner-Tool (Graduvation)

Developed a comprehensive Network Scanner GUI tool capable of scanning IP ranges to detect live hosts, open ports, and MAC addresses using Scapy, Tkinter, OS-level ping.

## Functionalities:
**IP Range Scanning:**
Scans a specified IP range (e.g., 192.168.1.1/24) to discover all live/active devices in the network using ARP protocol.

**MAC Address Resolution:**
Identifies and displays MAC addresses of all detected devices.

**Port Scanning:**
Scans commonly used ports (e.g., 21, 22, 80, 443, etc.) on each live host to identify open ports.

**Vulnerability Detection:**
Performs basic vulnerability checks by identifying insecure services running on open ports (e.g., FTP on port 21, Telnet on 23, SMB on 445).

**Ping Utility:**
Allows user to ping a specific IP address to check if the host is reachable or alive.

**GUI Interface:**
User-friendly interface using Tkinter, allowing:
Input of IP range
Start Scan button
Ping Host button
Clear Results button
Output window for displaying results

## Features:
| Feature                        | Description                                                               |
| ------------------------------ | ------------------------------------------------------------------------- |
| **Live Device Detection**      | Uses ARP requests to find devices on the network.                         |
| **Port Scanning**              | Checks for open TCP ports using socket connections.                       |
| **Basic Vulnerability Alerts** | Flags potentially vulnerable services (e.g., FTP, Telnet, SMB).           |
| **MAC Address Detection**      | Displays hardware (MAC) addresses of detected devices.                    |
| **Ping Testing**               | Tests host availability via ICMP ping.                                    |
| **Threaded Scanning**          | Runs network scan in a separate thread to keep the UI responsive.         |
| **Clear Scan Results**         | Button to clear the output window.                                        |
| **Modern GUI Design**          | Clean and responsive layout using `Tkinter` with themed fonts and colors. |

## Run:
```bash
python network scanner.py
```

## Output:
![image](https://github.com/user-attachments/assets/852412b3-884f-47d4-90e4-15a1d30fd863)
  

