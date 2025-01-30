import os
import shutil
import psutil
import time
from datetime import datetime
import requests
import hashlib
import threading
import pwd
import subprocess
from cryptography.fernet import Fernet
from IPLogger import logger
from Variables import requests_made, old_seen_programs, RATE_LIMIT, HEADERS, QUARANTINE

if not os.path.exists(QUARANTINE):
    os.makedirs(QUARANTINE)

###############################################################################################################

def load_encryption_key():
    try:
        with open("encryption_key.key", "rb") as key_file:
            key = key_file.read()
            return key
    except Exception as e:
        print(f"Error: {e}")
        logger(f"Error: {e}")
        return None

ENCRYPTION_KEY = load_encryption_key()

if ENCRYPTION_KEY is None:
    print("Error: Encryption Key")
    logger("Error: Encryption Key")
    exit(1)

cipher = Fernet(ENCRYPTION_KEY)

###############################################################################################################

def secure_quarantine_folder():
    # Read only folder
    os.chmod(QUARANTINE, 0o555)
    
    # Apply immutable flag, only works on linux rn
    subprocess.call(['chattr', '+i', QUARANTINE])

    # Change ownership
    os.chown(QUARANTINE, pwd.getpwnam('nobody').pw_uid, -1)

def encrypt_file(path_to_program, encryption_key):
    cipher = Fernet(encryption_key)
    with open(path_to_program, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)

    # Overwrite with encrypted data
    with open(path_to_program, 'wb') as f:
        f.write(encrypted_data)

###############################################################################################################

def handle_flagged_program(path_to_program):
    kill_program(path_to_program)
    quarantine_program(path_to_program)

def kill_program(path_to_program):
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.info['exe'] and os.path.samefile(proc.info['exe'], path_to_program):
                proc.kill()
                print(f"Killed PID {proc.info['pid']} program: {path_to_program}")
                logger(f"Killed PID {proc.info['pid']} program: {path_to_program}")
                return
    except Exception as e:
        print(f"[WARNING] ERROR KILLING: {path_to_program}: {e}")
        logger(f"[WARNING] ERROR KILLING: {path_to_program}: {e}")


def quarantine_program(path_to_program):
    try:
        if not os.path.exists(QUARANTINE):
            os.makedirs(QUARANTINE)
        
        secure_quarantine_folder()
        encrypt_file(path_to_program, ENCRYPTION_KEY)
        
        # Move the program
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        quarantined_file_name = f"{timestamp}_{os.path.basename(path_to_program)}"
        quarantined_path_to_program = os.path.join(QUARANTINE, quarantined_file_name)

        shutil.move(path_to_program, quarantined_path_to_program)
        print(f"Moved program: {path_to_program} to {quarantined_path_to_program}")
        logger(f"Moved program: {path_to_program} to {quarantined_path_to_program}")
        
        # Make program read only and non executable
        os.chmod(quarantined_path_to_program, 0o444)

    except Exception as e:
        print(f"[WARNING] ERROR QUARANTINING PROGRAM: {path_to_program}: {e}")
        logger(f"[WARNING] ERROR QUARANTINING PROGRAM: {path_to_program}: {e}")

###############################################################################################################

def calculate_file_hash(path_to_program):
    sha256_hash = hashlib.sha256()
    try:
        with open(path_to_program, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error Hash: {path_to_program}: {e}")
        logger(f"Error Hash: {path_to_program}: {e}")
        return None
    
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
                        handle_flagged_program(path_to_program)
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
                    handle_new_program(path_to_program)

        time.sleep(15)

def handle_new_program(path_to_program):
    print(f"Handling new file: {path_to_program}")
    scan_program_with_virustotal(path_to_program)

def start_monitoring():
    file_monitor_thread = threading.Thread(target=monitor_system)
    file_monitor_thread.daemon = True
    file_monitor_thread.start()

###############################################################################################################