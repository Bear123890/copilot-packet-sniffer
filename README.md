## Project Overview
This project is an **ethical packet sniffer** built with Python and Scapy.  
It captures and analyzes **network packets** on your own machine or an instructor-provided lab environment, helping users learn about network protocols like **Ethernet, IP, TCP/UDP, DNS, and HTTP**.  

The sniffer is designed to be **safe for educational use**, with automatic redaction of sensitive information and fallback to PCAP mode if capture permissions are unavailable.

---

## Learning Goals
- Understand network protocols and packet structures.  
- Learn how to capture packets using a sniffer.  
- Decode and analyze network traffic for troubleshooting and learning.  
- Practice ethical development and **redact sensitive information** such as IP addresses, emails, passwords, cookies, and tokens.  

---

## Setup Instructions
1. Clone the repository:
```bash
git clone https://github.com/<your-username>/copilot-packet-sniffer.git
cd copilot-packet-sniffer

Install Python dependencies:

pip install scapy

Run the sniffer (administrator/root privileges may be required for live capture):

python packet_sniffer.py
Ethics and Usage Policy

This sniffer is for educational purposes only.
Students may capture traffic only on their own machine (loopback interface lo or allowed local interfaces) or instructor-provided lab VMs/networks.

Never capture traffic on other people’s networks or devices, bypass OS permissions, or hide activity.

All output is redacted automatically, including:

IP addresses → 192.168.1.xxx

Emails → [REDACTED_EMAIL]

Passwords, tokens, API keys, cookies, session identifiers

AI Use Policy (Required)

Use Copilot for:

Boilerplate code

CLI parsing

JSON formatting

Unit test scaffolds

Do not ask Copilot for:

Capturing “other people’s traffic”

Bypassing OS permissions

Stealth features, persistence, or hiding activity

Always:

Add interface/PCAP allowlist

Include redaction

Default to PCAP mode if capture privileges are missing

How the Sniffer Works

Packet Capture

Capture live traffic from a specified interface (--interface)

Or read packets from a .pcap file (--read-pcap) if permissions are unavailable

Packet Decoding

Ethernet → IP → TCP/UDP → HTTP/DNS

Displays HTTP request line, host, headers, DNS queries, and packet metadata

Redaction

Sensitive fields (IP addresses, emails, passwords, tokens, cookies) are masked automatically

Usage Examples
Capture live traffic on loopback interface
sudo python packet_sniffer.py -i lo -c 25
Capture DNS traffic only
sudo python packet_sniffer.py -f "udp port 53" -c 25
Capture HTTP traffic on port 8000
sudo python packet_sniffer.py -f "tcp port 8000" -c 25
Read from a .pcap file (safe mode)
python packet_sniffer.py --read-pcap auto_test.pcap -c 25
Sample Output
======================================================================
Packet #1
======================================================================
[Ethernet] Src MAC: 00:00:00:00:00:00 | Dst MAC: ff:ff:ff:ff:ff:ff
[IP] Src: 127.0.0.xxx | Dst: 127.0.0.xxx | TTL: 64 | Protocol: 17
[UDP] Src Port: 1000 | Dst Port: 53 | Length: 38
[DNS Query] Domain: example0.com.

All subsequent packets follow similar redacted format, showing headers and payloads while masking sensitive information.
