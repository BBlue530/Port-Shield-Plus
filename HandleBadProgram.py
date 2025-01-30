import pwd
import subprocess
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime
import shutil
import psutil
import os
from Variables import QUARANTINE
from IPLogger import logger
from Immutable import ensure_immutable, remove_immutable, apply_immutable, remove_directory_immutable, apply_directory_immutable

###############################################################################################################

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

###############################################################################################################

def quarantine_program(path_to_program):
    try:
        if not os.path.exists(QUARANTINE):
            os.makedirs(QUARANTINE)

        stored_hash = calculate_file_hash(path_to_program)

        secure_quarantine_folder()
        
        # Move the program
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        quarantined_file_name = f"{timestamp}_{os.path.basename(path_to_program)}"
        quarantined_path_to_program = os.path.join(QUARANTINE, quarantined_file_name)
        
        remove_directory_immutable(quarantined_path_to_program)
        shutil.move(path_to_program, quarantined_path_to_program)
        current_hash = calculate_file_hash(quarantined_path_to_program)
        check_quarantine_integrity(current_hash, stored_hash)
        encrypt_file(quarantined_path_to_program, ENCRYPTION_KEY)
        os.chmod(quarantined_path_to_program, 0o000)
        apply_directory_immutable(quarantined_path_to_program)

        print(f"Moved program: {path_to_program} to {quarantined_path_to_program}")
        logger(f"Moved program: {path_to_program} to {quarantined_path_to_program}")
        
        ensure_immutable(quarantined_path_to_program)
        ensure_immutable(QUARANTINE)

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
    
###############################################################################################################


def secure_quarantine_folder():

    # Non executable directory
    os.chmod(QUARANTINE, 0o655)
    # Change ownership
    os.chown(QUARANTINE, pwd.getpwnam('nobody').pw_uid, -1)

def check_quarantine_integrity(current_hash, stored_hash):
    if current_hash != stored_hash:
        print(f"[ALERT] Integrity check failed for {current_hash}.")
        logger(f"[ALERT] Integrity check failed for {current_hash}.")
        # Optional: Trigger additional security measures, e.g., send alert, lock file, etc.

###############################################################################################################

def encrypt_file(path_to_program, encryption_key):
    cipher = Fernet(encryption_key)
    with open(path_to_program, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)

    # Overwrite with encrypted data
    with open(path_to_program, 'wb') as f:
        f.write(encrypted_data)

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