from scapy.all import conf, sniff, IP, TCP
import time
from collections import defaultdict
from Variables import ip_ports_accessed, PORTS_ACCESSED
from PortMonitoring.IPBlocking import block_ip
from IPLogger import logger

ip_ports_accessed = defaultdict(list)
TIME_GATE = 10

def sniff_packets(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP].src
            port = packet[TCP].dport

            current_time = time.time()

            ip_ports_accessed[ip] = {(p, t) for p, t in ip_ports_accessed[ip] if current_time - t <= TIME_GATE}
            ip_ports_accessed[ip].add((port, current_time))
            unique_ports = {p for p, _ in ip_ports_accessed[ip]}

            if len(unique_ports) > PORTS_ACCESSED:
                ports_attempted = ', '.join(map(str, unique_ports))
                print(f"[i] IP: {ip} accessed {len(unique_ports)} unique ports in {TIME_GATE} seconds. "
                      f"[i] Tried Ports: {ports_attempted}.")
                
                message = (f"[i] IP: {ip} accessed {len(unique_ports)} unique ports in {TIME_GATE} seconds. "
                           f"[i] Tried Ports: {ports_attempted}.")
                logger(message)

                block_ip(ip)

    except Exception as e:
        message = f"[!] ERROR: {e}"
        logger(message)