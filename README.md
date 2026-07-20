
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    print("=" * 60)

    if packet.haslayer(IP):
        ip = packet[IP]

        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print(f"Protocol       : {ip.proto}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload:")
            print(payload[:100])

print("Starting Network Sniffer...")
print("Press Ctrl+C to stop.\n")

sniff(prn=packet_callback, store=False)
