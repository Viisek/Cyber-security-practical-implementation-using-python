import scapy.all as scapy


def sniff_packets():
    print("[*] Sniffing packets on the local network...\n")
    scapy.sniff(prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Source: {ip_src} --> IP Destination: {ip_dst} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            tcp_src_port = packet[scapy.TCP].sport
            tcp_dst_port = packet[scapy.TCP].dport
            print(f"TCP Source Port: {tcp_src_port} --> TCP Destination Port: {tcp_dst_port}")

        elif packet.haslayer(scapy.UDP):
            udp_src_port = packet[scapy.UDP].sport
            udp_dst_port = packet[scapy.UDP].dport
            print(f"UDP Source Port: {udp_src_port} --> UDP Destination Port: {udp_dst_port}")

        elif packet.haslayer(scapy.ICMP):
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
            print(f"ICMP Type: {icmp_type} | ICMP Code: {icmp_code}")

        print("")

sniff_packets()

#npcap install
