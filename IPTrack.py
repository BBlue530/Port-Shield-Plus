from scapy.all import conf, sniff, IP, TCP
import time
from collections import defaultdict
from Variables import ip_ports_accessed, PORTS_ACCESSED
from IPBlocking import block_ip
from IPLogger import logger

ip_ports_accessed = defaultdict(list)
TIME_GATE = 10

def sniff_packets(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP].src
            port = packet[TCP].dport

            current_time = time.time()

            ip_ports_accessed[ip].append((port, current_time))

            ip_ports_accessed[ip] = [(ports, timestamp) for ports, timestamp in ip_ports_accessed[ip] if current_time - timestamp <= TIME_GATE]

            if len(ip_ports_accessed[ip]) > PORTS_ACCESSED:
                ports_attempted = ', '.join(map(str, [ports for ports, _ in ip_ports_accessed[ip]]))
                print(f"IP: {ip} Accessed: {len(ip_ports_accessed[ip])} Ports in: {TIME_GATE} seconds. "
                      f"Tried Ports: {ports_attempted}.")
                log_message = (f"IP: {ip} Accessed: {len(ip_ports_accessed[ip])} Ports in: {TIME_GATE} seconds. "
                               f"Tried Ports: {ports_attempted}.")
                logger(log_message, ip)

                block_ip(ip)

    except Exception as e:
        logger(f"Error: {e}", ip="unknown")