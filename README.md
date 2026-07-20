def process_packet(packet):
    print("\n" + "=" * 60)

    # Check if packet contains IP layer
    if packet.haslayer(IP):
        ip = packet[IP]

        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")
        print(f"Protocol Number: {ip.proto}")

        # Detect Protocol
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol       : TCP")
            print(f"Source Port    : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol       : UDP")
            print(f"Source Port    : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        # Display Payload
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                print("Payload:")
                print(payload.decode(errors="ignore"))
            except:
                print("Payload: Unable to decode")

print("=" * 60)
print("        BASIC NETWORK SNIFFER")
print("=" * 60)
print("Capturing packets... Press Ctrl+C to stop.\n")

sniff(prn=process_packet, store=False)
