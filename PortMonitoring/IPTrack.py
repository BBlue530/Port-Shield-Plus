from scapy.all import conf, sniff, IP, TCP
import time
from Variables import ip_ports_accessed, ip_syn_count, PORTS_ACCESSED, TIME_GATE, SYN_FLOOD_THRESHOLD
from PortMonitoring.IPBlocking import block_ip
from IPLogger import logger

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
                print(f"[i] IP: {ip} accessed {len(unique_ports)} unique ports in {TIME_GATE} seconds Tried Ports: {ports_attempted}.")
                message = f"[i] IP: {ip} accessed {len(unique_ports)} unique ports in {TIME_GATE} seconds Tried Ports: {ports_attempted}."
                logger(message)

                block_ip(ip)

            # Check if packet is a SYN request
            if packet[TCP].flags == 'S':
                ip_syn_count[ip] += 1
                if ip_syn_count[ip] > SYN_FLOOD_THRESHOLD:
                    # If the SYN count gets to high block the IP
                    print(f"[i] SYN flood detected from IP: {ip} with {ip_syn_count[ip]} SYN packets.")
                    message = f"[i] SYN flood detected from IP: {ip} with {ip_syn_count[ip]} SYN packets."
                    logger(message)
                    block_ip(ip)
                else:
                    print(f"[i] SYN packet received from {ip}. Total SYN count: {ip_syn_count[ip]}")
                
    except Exception as e:
        message = f"[!] ERROR: {e}"
        logger(message)

###############################################################################################################

def start_sniffing():
    try:
        sniff(prn=sniff_packets, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\nStop.")
    except Exception as e:
        print(f"[!] ERROR: {e}")

###############################################################################################################