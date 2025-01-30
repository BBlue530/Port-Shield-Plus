import os
import time
import requests
import threading
from IPLogger import logger
from Variables import requests_made, old_seen_programs, RATE_LIMIT, HEADERS, QUARANTINE
from HandleBadProgram import calculate_file_hash, kill_program, quarantine_program

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
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                json_response = response.json()
                analysis = json_response['data']['attributes']
                status = analysis['status']
                if status == 'completed':
                    results = analysis['results']
                    print(f"Scan completed for: {path_to_program}")
                    logger(f"Scan completed for: {path_to_program}")
                    print(f"Scan results: {results}")
                    logger(f"Scan results: {results}")
                    detected = sum([1 for engine in results.values() if engine['category'] == 'malicious'])
                    if detected > 0:
                        print(f"[WARNING]: File {path_to_program} detected!")
                        logger(f"[WARNING]: File {path_to_program} detected!")
                        kill_program(path_to_program)
                        quarantine_program(path_to_program)
                    else:
                        print(f"Program {path_to_program} is safe.")
                        logger(f"Program {path_to_program} is safe.")
                else:
                    print(f"Scan for program {path_to_program}...")
            else:
                print(f"Error scanning: {path_to_program}: {response.status_code}: {response.text}")
                logger(f"Error scanning: {path_to_program}: {response.status_code}: {response.text}")
        except Exception as e:
            print(f"Error: {e}")
            logger(f"Error: {e}")
    else:
        print(f"Error Hash: {path_to_program}.")
        logger(f"Error Hash: {path_to_program}.")

###############################################################################################################

def monitor_system():
    print("Monitoring system...")

    while True:
        for root, _, files in os.walk("/"):
            for file in files:
                path_to_program = os.path.join(root, file)
                
                if path_to_program not in old_seen_programs:
                    old_seen_programs.add(path_to_program)
                    print(f"New program found: {path_to_program}")
                    scan_program_with_virustotal(path_to_program)

        time.sleep(15)

def start_monitoring():
    file_monitor_thread = threading.Thread(target=monitor_system)
    file_monitor_thread.daemon = True
    file_monitor_thread.start()

###############################################################################################################