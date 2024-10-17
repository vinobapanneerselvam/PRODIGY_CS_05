import socket
import struct
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            protocol = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            payload = b'No payload'

            if TCP in packet:
                tcp_layer = packet[TCP]
                payload = bytes(tcp_layer.payload)
                protocol = 6  # TCP Protocol number
            elif UDP in packet:
                udp_layer = packet[UDP]
                payload = bytes(udp_layer.payload)
                protocol = 17  # UDP Protocol number

            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload}")
        else:
            print("Error processing packet: IP layer not found")

    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

