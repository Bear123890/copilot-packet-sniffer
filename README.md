# Project Overview
This project is a packet sniffer designed to capture and analyze network packets. It helps users understand network traffic and learn various protocols.

# Learning Goals
- Understand network protocols.
- Learn how to capture packets using a sniffer.
- Analyze network traffic for troubleshooting.

# Setup Instructions
1. Clone the repository using `git clone https://github.com/Bear123890/copilot-packet-sniffer.git`
2. Navigate to the project directory.
3. Install the required dependencies using `pip install -r requirements.txt`.
4. Run the application with `python sniffer.py`.

# Ethics and Usage Policy
This tool should be used ethically and responsibly. Do not capture packets on networks without permission.

# AI Use Policy
Use Copilot for: Boilerplate code, CLI parsing,JSON formatting, Unit test scaffolds

Do not ask Copilot for: Capturing “other people’s traffic”, Bypassing OS permissions, Stealth features, persistence, or hiding activity

Always: Add interface/PCAP allowlist, Include redaction, Default to PCAP mode if capture privileges are missing

# How the Sniffer Works
The sniffer operates by capturing packets on the network interface and analyzing their header information. It classifies packets based on their protocols and provides insights into data flow.

# Usage Examples
- To start the packet sniffer, run:
  ```bash
  python sniffer.py
  ```
- To filter by a specific protocol, use:
  ```bash
  python sniffer.py --protocol TCP
  ```

# Deliverables
- A fully functional packet sniffer.
- Documentation on usage and setup.
- Example outputs demonstrating the tool's capabilities.
