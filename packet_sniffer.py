import re
import sys
import argparse
from typing import Optional
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, get_if_list
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

class PacketRedactor:
    """Handles redaction of sensitive data in captured packets"""

    @staticmethod
    def redact_ip(ip_address: str) -> str:
        parts = ip_address.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return ip_address

    @staticmethod
    def redact_email(text: str) -> str:
        return re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)

    @staticmethod
    def redact_sensitive_params(text: str) -> str:
        text = re.sub(
            r'(password|pwd|passwd|token|api[_-]?key|session|auth|bearer|apikey)=([^\s&]+)',
            r'\1=[REDACTED]', flags=re.IGNORECASE)
        text = re.sub(r'(Authorization|Authorization:)\s+([^\s]+)', r'\1 [REDACTED]', flags=re.IGNORECASE)
        text = re.sub(r'(Cookie|Cookie:)\s+([^\r\n]+)', r'\1 [REDACTED]', flags=re.IGNORECASE)
        return text

    @staticmethod
    def redact_payload(payload: str) -> str:
        payload = PacketRedactor.redact_email(payload)
        payload = PacketRedactor.redact_sensitive_params(payload)
        return payload


class PacketSniffer:
    """Main packet sniffer class"""

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "", count: int = 25, read_pcap: Optional[str] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.read_pcap = read_pcap
        self.packet_count = 0
        self.redactor = PacketRedactor()

    def packet_callback(self, packet) -> None:
        self.packet_count += 1
        print(f"\n{'='*70}")
        print(f"Packet #{self.packet_count}")
        print(f"{'='*70}")

        if Ether in packet:
            eth = packet[Ether]
            print(f"[Ethernet] Src MAC: {eth.src} | Dst MAC: {eth.dst}")

        if IP in packet:
            ip_layer = packet[IP]
            src_ip = self.redactor.redact_ip(ip_layer.src)
            dst_ip = self.redactor.redact_ip(ip_layer.dst)
            print(f"[IP] Src: {src_ip} | Dst: {dst_ip} | TTL: {ip_layer.ttl} | Protocol: {ip_layer.proto}")

            if TCP in packet:
                tcp_layer = packet[TCP]
                flags = tcp_layer.flags
                print(f"[TCP] Src Port: {tcp_layer.sport} | Dst Port: {tcp_layer.dport} | Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack} | Flags: {flags}")
                if tcp_layer.dport == 8000 or tcp_layer.sport == 8000:
                    self._decode_http(packet)

            elif UDP in packet:
                udp_layer = packet[UDP]
                print(f"[UDP] Src Port: {udp_layer.sport} | Dst Port: {udp_layer.dport} | Length: {udp_layer.len}")
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    self._decode_dns(packet)

        if Raw in packet:
            self._display_payload(packet)

    def _decode_http(self, packet) -> None:
        if Raw in packet:
            payload = packet[Raw].load
            try:
                http_data = payload.decode('utf-8', errors='ignore')
                lines = http_data.split('\r\n')
                if lines and lines[0].split(' ')[0] in ['GET','POST','PUT','DELETE','HEAD','OPTIONS']:
                    print(f"[HTTP Request] {lines[0]}")
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            host = line.split(':',1)[1].strip()
                            print(f"[HTTP Host] {host}")
                            break
                    print("[HTTP Headers]")
                    for line in lines[1:]:
                        if line and ':' in line:
                            print(f"  {self.redactor.redact_sensitive_params(line)}")
            except:
                pass

    def _decode_dns(self, packet) -> None:
        if DNS in packet and DNSQR in packet and packet[DNS].qr == 0:
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            print(f"[DNS Query] Domain: {qname}")

    def _display_payload(self, packet) -> None:
        try:
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                payload_str = self.redactor.redact_payload(payload_str)
                print(f"[Payload] {payload_str[:200]}{'...' if len(payload_str)>200 else ''}")
            except:
                print(f"[Payload (hex)] {payload[:50].hex()}...")
        except:
            pass

    def start_sniffing(self) -> None:
        print("\n" + "*"*70)
        print("Ethical Packet Sniffer - Loopback / Auto PCAP Mode")
        print("*"*70)

        if self.read_pcap:
            packets = rdpcap(self.read_pcap)
            for packet in packets[:self.count]:
                self.packet_callback(packet)
        else:
            print(f"Interface: {self.interface}")
            print(f"Filter: {self.bpf_filter}")
            print(f"Capture Count: {self.count}\n[*] Starting capture...")
            try:
                sniff(iface=self.interface, prn=self.packet_callback, filter=self.bpf_filter, count=self.count, store=False)
            except PermissionError:
                print("[!] Root/Administrator privileges required.")
                sys.exit(1)
            except Exception as e:
                print(f"[!] Error: {e}")
                sys.exit(1)

        print(f"\nCapture Complete. Total packets: {self.packet_count}\n{'*'*70}")


def generate_test_pcap(filename="auto_test.pcap", count=25):
    """Automatically generate a local PCAP with HTTP + DNS packets"""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.layers.dns import DNS, DNSQR

    packets = []
    for i in range(count):
        if i % 5 == 0:  # Every 5th packet is DNS
            pkt = Ether()/IP(dst="127.0.0.1")/UDP(dport=53, sport=1000+i)/DNS(rd=1, qd=DNSQR(qname=f"example{i}.com"))
        else:  # HTTP packet
            pkt = Ether()/IP(dst="127.0.0.1")/TCP(dport=8000, sport=1024+i)/Raw(
                load=f"GET /test{i} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"[*] Generated test PCAP: {filename} with {count} packets (HTTP + DNS)")
    return filename


def main():
    parser = argparse.ArgumentParser(description="Ethical Packet Sniffer - Auto PCAP fallback")
    parser.add_argument('-i','--interface', type=str, default=None, help="Loopback interface")
    parser.add_argument('-f','--filter', type=str, default="", help="BPF filter")
    parser.add_argument('-c','--count', type=int, default=25, help="Number of packets")
    parser.add_argument('--read-pcap', type=str, default=None, help="PCAP file to read")
    args = parser.parse_args()

    # Detect if lo exists
    interface_to_use = None
    if args.read_pcap:
        interface_to_use = None
    elif args.interface is None or args.interface=="lo":
        if "lo" in get_if_list():
            interface_to_use = "lo"
        else:
            print("[!] Loopback interface 'lo' not found. Generating test PCAP for PyCharm/Windows...")
            args.read_pcap = generate_test_pcap(count=args.count)

    if not args.filter:
        args.filter = "tcp port 8000 or udp port 53"

    sniffer = PacketSniffer(
        interface=interface_to_use,
        bpf_filter=args.filter,
        count=args.count,
        read_pcap=args.read_pcap
    )

    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
