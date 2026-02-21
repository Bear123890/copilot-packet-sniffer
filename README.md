# CoPilot Packet Sniffer

## Project Description
This project is an **ethical packet sniffer** built with Python and Scapy.  
It captures and analyzes **network packets** on your own machine or an instructor-provided lab environment, helping users learn about network protocols like **Ethernet, IP, TCP/UDP, DNS, and HTTP**.
The sniffer is designed to be **safe for educational use**, with automatic redaction of sensitive information and fallback to PCAP mode if capture permissions are unavailable.

## Features
- Real-time packet capturing
- User-friendly interface for display and filtering of packets
- Support for various protocols (TCP, UDP, ICMP, etc.)
- Filtering and search capabilities to find relevant traffic instantly
- Export captured packets in various formats (PCAP, CSV)

## Requirements
- Python 3.6+
- Scapy library (Python networking library)

## Installation
To install CoPilot Packet Sniffer, clone the repository and install the required dependencies:

```bash
git clone https://github.com/Bear123890/copilot-packet-sniffer.git
cd copilot-packet-sniffer
pip install -r requirements.txt
```
Install Python dependencies:
pip install scapy

Run the sniffer (administrator/root privileges may be required for live capture):
python packet_sniffer.py

## Ethics and Usage Policy
This sniffer is for educational purposes only.
Students may capture traffic only on their own machine (loopback interface lo or allowed local interfaces) or instructor-provided lab VMs/networks.
Never capture traffic on other people’s networks or devices, bypass OS permissions, or hide activity.

All output is redacted automatically, including:

IP addresses → 192.168.1.xxx

Emails → [REDACTED_EMAIL]

Passwords, tokens, API keys, cookies, session identifiers

## AI Use Policy
Use Copilot for: Boilerplate code, CLI parsing, JSON formatting,Unit test scaffolds

Do not ask Copilot for: Capturing “other people’s traffic”, Bypassing OS permissions, Stealth features, persistence, or hiding activity

Always: Add interface/PCAP allowlist, Include redaction, Default to PCAP mode if capture privileges are missing

## How the Sniffer Works

1. Packet Capture:
Capture live traffic from a specified interface (--interface) Or read packets from a .pcap file (--read-pcap) if permissions are unavailable

2. Packet Decoding:
 Ethernet → IP → TCP/UDP → HTTP/DNS, Displays HTTP request line, host, headers, DNS queries, and packet metadata

 3. Redaction:
 Sensitive fields (IP addresses, emails, passwords, tokens, cookies) are masked automatically
