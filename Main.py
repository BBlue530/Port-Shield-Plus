from scapy.all import sniff
from PortMonitoring.IPTrack import start_sniffing
from ProgramMonitoring.MonitorSystem import start_program_monitoring
import platform
import threading

current_os = platform.system().lower()

###############################################################################################################

if current_os == 'linux':
    
    print("Start...")

    program_monitor_thread = threading.Thread(target=start_program_monitoring, daemon=True)
    sniff_packets_thread = threading.Thread(target=start_sniffing, daemon=True)
    
    program_monitor_thread.start()
    sniff_packets_thread.start()

    sniff_packets_thread.join()

elif current_os == 'windows':
    print("[i] Program doesn't run on Windows.")
    print("Exit...")

###############################################################################################################