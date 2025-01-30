from scapy.all import sniff
from IPTrack import sniff_packets
from BlockHash import start_monitoring
import platform

current_os = platform.system().lower()

print("Start...")

# I have not made all the functions of this work on windows yet but i will later on but for now this will have to work
if current_os == 'linux':
    start_monitoring()
    try:
        sniff(prn=sniff_packets, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\nStop.")
    except Exception as e:
        print(f"Error: {e}")
elif current_os == 'windows':
    print("Program doesnt run on windows.")
    print("Exit...")