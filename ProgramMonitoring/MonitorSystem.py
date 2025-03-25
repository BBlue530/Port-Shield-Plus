import os
import time
import threading
from IPLogger import logger
from Variables import old_seen_programs, QUARANTINE
from ProgramMonitoring.HandleBadProgram import  quarantine_program
from PerformanceMonitor import start_timer, check_timer
from ProgramMonitoring.HandleNewProgram import handle_new_program

if not os.path.exists(QUARANTINE):
    os.makedirs(QUARANTINE)

###############################################################################################################

def monitor_system():
    start_time = start_timer()
    current_programs = set()
    current_programs = get_current_programs()
    old_seen_programs.update(current_programs)
    print("Monitoring system...")

    while True:

        check_timer(start_time, function="Before Walk")
        if os.path.exists(QUARANTINE):
            quarantine_exists = True
        else:
            quarantine_exists = False

        for root, _, files in os.walk("/"):
            if "/proc" in root or "/sys" in root or "/dev" in root:
                continue
            if root.startswith("/tmp") or root.startswith("/var/tmp") or root.startswith("/home/kali/.cache"):
                continue
            if quarantine_exists and QUARANTINE in root:
                continue
            for file in files:
                if ".lock" in file or ".swp" in file or ".pyc" in file or ".log" in file:
                    continue
                path_to_program = os.path.join(root, file)
                current_programs.add(path_to_program)
        check_timer(start_time, function="After Walk")

        new_programs = current_programs - old_seen_programs

        for new_file in new_programs:
            print(f"[i] New program found: {new_file}")
            handle_new_program(new_file)

        old_seen_programs.update(new_programs)
        time.sleep(15)

def start_program_monitoring():
    file_monitor_thread = threading.Thread(target=monitor_system)
    file_monitor_thread.daemon = True
    file_monitor_thread.start()

def get_current_programs():
    current_programs = set()
    for root, _, files in os.walk("/"):
        for file in files:
            if "/proc" in root or "/sys" in root or "/dev" in root:
                continue
            path_to_program = os.path.join(root, file)
            current_programs.add(path_to_program)
    return current_programs

###############################################################################################################