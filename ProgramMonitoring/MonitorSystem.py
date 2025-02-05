import os
import time
import requests
import threading
from IPLogger import logger
from Variables import requests_made, old_seen_programs, RATE_LIMIT, HEADERS, QUARANTINE
from ProgramMonitoring.HandleBadProgram import calculate_file_hash, kill_program, quarantine_program
from PerformanceMonitor import start_timer, check_timer
from ProgramMonitoring.SubmitAndScan import check_scan_status, submit_file_for_scan

if not os.path.exists(QUARANTINE):
    os.makedirs(QUARANTINE)

###############################################################################################################
    
def rate_limited_request(function):

    def wrapper(*args, **kwargs):
        # Clean up old scans
        current_time = time.time()
        while requests_made and current_time - requests_made[0] > 60:
            requests_made.popleft()
        
        if len(requests_made) < RATE_LIMIT:
            result = function(*args, **kwargs)
            requests_made.append(time.time())  # Add the current scan to a que
            return result
        else:
            print("Rate Limit...")
            time.sleep(60 - (current_time - requests_made[0]))
            return wrapper(*args, **kwargs)
    
    return wrapper

@rate_limited_request
def scan_program_with_virustotal(path_to_program):
    file_hash = calculate_file_hash(path_to_program)
    if file_hash:
        url = f"https://www.virustotal.com/api/v3/programs/{file_hash}"
        try:
            response = requests.get(url, headers=HEADERS)
            json_response = response.json()

            if response.status_code == 404:
                print(f"[!] ERROR: {path_to_program} not found in VirusTotal.")
                message = f"[!] ERROR: {path_to_program} not found in VirusTotal."
                logger(message)

                print(f"[i] Submitting file {path_to_program} for scan...")
                analysis_id = submit_file_for_scan(path_to_program)

                if analysis_id:
                    print(f"[i] File {path_to_program} uploaded. Waiting for scan to complete...")
                    time.sleep(60)
                    check_scan_status(analysis_id, path_to_program)
                return

            if response.status_code != 200:
                print(f"[!] ERROR: {path_to_program}: {response.status_code}")
                message = f"[!] ERROR: {path_to_program}: {response.status_code}"
                logger(message)
                return

            if "data" in json_response and "attributes" in json_response["data"]:
                analysis = json_response["data"]["attributes"]

                if "status" in analysis:
                    status = analysis["status"]
                    if status == "completed":
                        results = analysis.get("results", {})
                        print(f"[i] Scan completed for: {path_to_program}")
                        message = f"[i] Scan completed for: {path_to_program}"
                        logger(message)
                        print(f"[i] Scan results: {results}")
                        message = f"[i] Scan results: {results}"
                        logger(message)
                        detected = sum([1 for engine in results.values() if engine["category"] == "malicious"])

                        if detected > 0:
                            print(f"[!] WARNING: {path_to_program} detected!")
                            message = f"[!] WARNING: {path_to_program} detected!"
                            logger(message)
                            kill_program(path_to_program)
                            quarantine_program(path_to_program)
                        else:
                            print(f"[i] Program {path_to_program} is safe.")
                            message = f"[i] Program {path_to_program} is safe."
                            logger(message)

                    else:
                        print(f"[i] Scan for program {path_to_program} is still in progress...")

            else:
                print(f"[!] ERROR scanning: {path_to_program}: {response.status_code}")
                message = f"[!] ERROR scanning: {path_to_program}: {response.status_code}"
                logger(message)

        except Exception as e:
            print(f"[!] ERROR: {e}")
            message = f"[!] ERROR: {e}"
            logger(message)

    else:
        print(f"[!] ERROR Hash: {path_to_program}.")
        message = f"[!] ERROR Hash: {path_to_program}."
        logger(message)

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
            scan_program_with_virustotal(new_file)

        old_seen_programs.update(new_programs)
        time.sleep(15)

def start_monitoring():
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