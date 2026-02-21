from scapy.all import *

class PacketSniffer:
    def __init__(self, filter_rule=None):
        self.filter_rule = filter_rule

    def start_sniffing(self):
        print("Starting packet capture...")
        sniff(filter=self.filter_rule, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        decoded_packet = self.decode_packet(packet)
        redacted_packet = self.redact_packet(decoded_packet)
        self.display_packet(redacted_packet)

    def decode_packet(self, packet):
        if IP in packet:
            return packet[IP].summary()
        return str(packet)

    def redact_packet(self, packet):
        # Example: Redact sensitive information, such as IP addresses
        return packet.replace('192.168.', '***.***.***.')

    def display_packet(self, packet):
        print(packet)

if __name__ == '__main__':
    sniffer = PacketSniffer(filter_rule='ip')  # Filter for IP packets
    sniffer.start_sniffing()