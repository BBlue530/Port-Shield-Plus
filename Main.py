from scapy.all import sniff
from IPTrack import sniff_packets

print("Start...")
try:
    sniff(prn=sniff_packets, store=0, filter="ip")
except KeyboardInterrupt:
    print("\nStop.")
except Exception as e:
    print(f"Error: {e}")