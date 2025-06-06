# 🕵️‍♂️ Python Network Sniffer

This is a simple real-time **network packet sniffer** built using Python and the Scapy library.

## 🔧 Features

* Captures live packets from the network interface
* Identifies protocols: **TCP**, **UDP**, **ICMP**
* Displays **Source IP → Destination IP** in real-time
* Lightweight & beginner-friendly

## How It Works

The script uses Scapy's `sniff()` function to capture network packets and analyze their protocol layers. It prints protocol type and source/destination IP addresses to the console in real time.

##  Setup

### For Windows:

1. Install Npcap(required for packet capturing on Windows).
2. Install Python 3 if not already installed.
3. Install Scapy via pip:

   ```bash
   pip install scapy
   ```
4. Run the sniffer:

   ```bash
   python sniffer.py
   ```

### For Linux:

1. Install Python 3 and pip (if not already installed).
2. Install Scapy:

   ```bash
   sudo pip3 install scapy
   ```
3. Run the sniffer with root privileges:

   ```bash
   sudo python3 sniffer.py
   ```

## Example Output

```
[+] TCP Packet: 192.168.1.2 → 142.250.183.110
[+] UDP Packet: 192.168.1.5 → 192.168.1.1
[+] ICMP Packet: 192.168.1.4
## 📦 Dependencies

* Python 3.x
* [Scapy](https://scapy.readthedocs.io/en/latest/)
* [Npcap (for Windows)](https://nmap.org/npcap/)
