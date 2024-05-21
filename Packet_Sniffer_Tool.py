from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}\tProtocol: {proto}")

        if TCP in packet:
            payload = str(packet[TCP].payload)
            print(f"Payload: {payload}")

        elif UDP in packet:
            payload = str(packet[UDP].payload)
            print(f"Payload: {payload}")

# Replace 'eth0' with your network interface
sniff(iface='eth0', prn=packet_callback, store=0)
