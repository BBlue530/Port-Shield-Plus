import pwd
from cryptography.fernet import Fernet
import hashlib
from datetime import datetime
import shutil
import psutil
import os
import signal
import time
from Variables import QUARANTINE, directory_permissions, program_permissions
from IPLogger import logger
from ProgramMonitoring.Immutable import remove_directory_immutable, apply_directory_immutable
from SecurityChecks.MonitorSecurity import check_quarantine_integrity, pid_still_running, encryption_check, quarantine_check, ensure_immutable, permissionns_check

###############################################################################################################

def kill_program(path_to_program):
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.info['exe'] and os.path.samefile(proc.info['exe'], path_to_program):
                proc.kill()
                pid = proc.info['pid']

                print(f"[i] Killed PID {proc.info['pid']} program: {path_to_program}")
                message = f"[i] Killed PID {proc.info['pid']} program: {path_to_program}"
                logger(message)
                time.sleep(5)

                if psutil.pid_exists(pid):
                    message = f"[!] WARNING: {pid} Running"
                    logger(message)
                    force_kill(pid, path_to_program)

                return
    except Exception as e:
        print(f"[!] WARNING ERROR KILLING: {path_to_program}: {e}")
        message = f"[!] WARNING ERROR KILLING: {path_to_program}: {e}"
        logger(message)

def force_kill(pid, path_to_program):
    try:

        if os.name == "nt":
            proc = psutil.Process(pid)
            proc.terminate()
        else:
            os.kill(pid, signal.SIGKILL)
        
        if psutil.pid_exists(pid):
            pid_still_running(pid, path_to_program)

        else:
            message = f"[i] Forcefully killed PID {pid}"
            logger(message)

    except Exception as e:
        message = f"[!] ERROR Force Kill Failed: {pid}: {e}"
        logger(message)

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
        
        remove_directory_immutable(QUARANTINE)
        shutil.move(path_to_program, quarantined_path_to_program)
        current_hash = calculate_file_hash(quarantined_path_to_program)
        check_quarantine_integrity(current_hash, stored_hash, path_to_program, quarantined_path_to_program)

        encrypt_file(quarantined_path_to_program, stored_hash, ENCRYPTION_KEY)
        encryption_check(quarantined_path_to_program, stored_hash, ENCRYPTION_KEY)

        apply_directory_immutable(QUARANTINE)
        ensure_immutable(quarantined_path_to_program)
        ensure_immutable(QUARANTINE)

        print(f"[i] Moved program: {path_to_program} to {quarantined_path_to_program}")
        message = f"[i] Moved program: {path_to_program} to {quarantined_path_to_program}"
        logger(message)

        os.chmod(quarantined_path_to_program, program_permissions) # Gotta make it make everything inside the folder of the program read only. So ill prolly end up making it make a folder that puts it in quarantine
        permissionns_check(quarantined_path_to_program)

        quarantine_check()

        print(f"[i] Quarantine Of: {quarantined_path_to_program} Worked.")
        message = f"[i] Quarantine Of: {quarantined_path_to_program} Worked."
        logger(message)

    except Exception as e:
        print(f"[!] WARNING ERROR QUARANTINING PROGRAM: {path_to_program}: {e}")
        message = f"[!] WARNING ERROR QUARANTINING PROGRAM: {path_to_program}: {e}"
        logger(message)

###############################################################################################################

def calculate_file_hash(path_to_program):
    sha256_hash = hashlib.sha256()
    try:
        with open(path_to_program, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[!] ERROR Hash: {path_to_program}: {e}")
        message = f"[!] ERROR Hash: {path_to_program}: {e}"
        logger(message)
        return None
    
###############################################################################################################

def secure_quarantine_folder():

    # Non executable directory
    os.chmod(QUARANTINE, directory_permissions)
    # Change ownership
    os.chown(QUARANTINE, pwd.getpwnam('nobody').pw_uid, -1)

###############################################################################################################

def encrypt_file(quarantined_path_to_program, stored_hash, ENCRYPTION_KEY):
    encrypted_hash = calculate_file_hash(quarantined_path_to_program)
    if encrypted_hash == stored_hash:
        cipher = Fernet(ENCRYPTION_KEY)
        with open(quarantined_path_to_program, 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)

    # Overwrite with encrypted data
        with open(quarantined_path_to_program, 'wb') as f:
            f.write(encrypted_data)

def load_encryption_key():
    try:
        with open("encryption_key.key", "rb") as key_file:
            key = key_file.read()
            return key
    except Exception as e:
        print(f"[!] ERROR: {e}")
        message = f"[!] ERROR: {e}"
        logger(message)
        return None

ENCRYPTION_KEY = load_encryption_key()

if ENCRYPTION_KEY is None:
    print("[!] ERROR: Encryption Key")
    message = "[!] ERROR: Encryption Key"
    logger(message)
    exit(1)

cipher = Fernet(ENCRYPTION_KEY)

###############################################################################################################