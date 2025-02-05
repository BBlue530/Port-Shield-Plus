import os
import psutil
import time
import signal
import subprocess
from cryptography.fernet import Fernet
from Variables import QUARANTINE, program_permissions, directory_permissions
from IPLogger import logger
from SecurityChecks.NuclearOption import last_line_defense
from ProgramMonitoring.Immutable import apply_immutable

###############################################################################################################

def check_quarantine_integrity(current_hash, stored_hash, path_to_program, quarantined_path_to_program):
    if current_hash != stored_hash:
        print(f"[!] WARNING Integrity check failed for {current_hash}.")
        message = f"[!] WARNING Integrity check failed for {current_hash}."
        logger(message)

        encryption_check(quarantined_path_to_program, stored_hash, ENCRYPTION_KEY)
        encryption_check(path_to_program, stored_hash, stored_hash, ENCRYPTION_KEY)
        permissionns_check(quarantined_path_to_program)
        permissionns_check(path_to_program)

# Yes i know i can do this in a nicer way but thats work for another day
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

def encryption_check(encryption_of_path_to_program, stored_hash, ENCRYPTION_KEY):

    if not os.path.exists(encryption_of_path_to_program):
        print(f"[!] WARNING: Path does not exist: {encryption_of_path_to_program}.")
        message = f"[!] WARNING: Path does not exist: {encryption_of_path_to_program}."
        logger(message)
        return
    
    from ProgramMonitoring.HandleBadProgram import calculate_file_hash
    encrypted_hash = calculate_file_hash(encryption_of_path_to_program)
    if encrypted_hash == stored_hash:
        print(f"[!] WARNING ENCRYPTION FAILED: {encryption_of_path_to_program}.")
        message = f"[!] WARNING ENCRYPTION FAILED: {encryption_of_path_to_program}."
        logger(message)

        from ProgramMonitoring.HandleBadProgram import encrypt_file
        encrypt_file(encryption_of_path_to_program, stored_hash, ENCRYPTION_KEY)

        new_encrypted_hash = calculate_file_hash(encryption_of_path_to_program)
        if new_encrypted_hash == stored_hash:
            print(f"[!] WARNING ENCRYPTION FAILED ON: {encryption_of_path_to_program}")
            message = f"[!] WARNING ENCRYPTION FAILED ON: {encryption_of_path_to_program}"
            logger(message)
            last_line_defense(encryption_of_path_to_program)

    else:
        message = f"[i] Encryption worked {encryption_of_path_to_program}."
        logger(message)

###############################################################################################################

def quarantine_check():
    for filename in os.listdir(QUARANTINE):
        file = os.path.join(QUARANTINE, filename)
        if file == QUARANTINE:
            continue
        
        if os.path.isfile(file):
            writable_access_check(file)

def writable_access_check(file):
    try:
        os.chmod(file, program_permissions)
        apply_immutable(file)

        with open(file, "a"): 
            print(f"[!] WARNING: {file} IS WRITEABLE.")
            message = f"[!] WARNING: {file} IS WRITEABLE."
            logger(message)
            os.chmod(file, program_permissions)
            apply_immutable(file)

            with open(file, "a"):
                print(f"[!] WARNING: {file} IS STILL WRITEABLE.")
                message = f"[!] WARNING: {file} IS STILL WRITEABLE."
                logger(message)
                last_line_defense(file)

    except IOError:
        message = f"[i] Quarantine {file} is protected from writing."
        logger(message)

###############################################################################################################

def pid_still_running(pid, path_to_program):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        message = f"[i] Terminated PID: {pid}"
        logger(message)
        
        time.sleep(5)
        if psutil.pid_exists(pid):
            message = f"[!] PID: {pid} still running"
            logger(message)
            os.kill(pid, signal.SIGKILL)
            time.sleep(5)
            
        if psutil.pid_exists(pid):
            proc.suspend()
            time.sleep(1)
            proc.kill()
            message = f"[!] Suspended/Killed PID: {pid}"
            logger(message)
        
        if psutil.pid_exists(pid):
            kill_parent_program(pid)
        
        if psutil.pid_exists(pid):
            message = f"[!] Last Kill of PID attempt: {pid}"
            logger(message)
            if os.name == "nt":
                os.system(f"taskkill /F /PID {pid}")
            else:
                os.system(f"killall -9 {psutil.Process(pid).name()}")
            time.sleep(2)
        
        if psutil.pid_exists(pid):
            print(f"[!] ERROR PID: {pid} STILL RUNNINNG.")
            message = f"[!] ERROR PID: {pid} STILL RUNNINNG."
            logger(message)
            last_line_defense(path_to_program)
        else:
            message = f"PID: {pid} killed."
            logger(message)
    except Exception as e:
        print(f"[!] ERROR PID: {pid} STILL RUNNINNG: {e}")
        message = f"[!] ERROR PID: {pid} STILL RUNNINNG: {e}"
        logger(message)
        last_line_defense(path_to_program)

def kill_parent_program(pid):
    try:
        parent_pid = psutil.Process(pid).parent().pid
        message = f"[i] Kill of parent program PID: {parent_pid} from: {pid}."
        logger(message)
        os.kill(parent_pid, signal.SIGKILL)
    except Exception as e:
        print(f"[!] ERROR Kill Parent From PID: {pid}: {e}")
        message = f"[!] ERROR Kill Parent From PID: {pid}: {e}"
        logger(message)

###############################################################################################################

def ensure_immutable(quarantined_program):
        immutable_flag = subprocess.check_output(["lsattr", quarantined_program]).decode("utf-8")
        if "i" not in immutable_flag:
            apply_immutable(quarantined_program)

            immutable_flag = subprocess.check_output(["lsattr", quarantined_program]).decode("utf-8")
            if "i" not in immutable_flag:
                print(f"[!] WARNING: {quarantined_program} IMMUTABLE FLAG: {immutable_flag}")
                message = f"[!] WARNING: {quarantined_program} IMMUTABLE FLAG: {immutable_flag}"
                logger(message)
                last_line_defense(quarantined_program)

###############################################################################################################

def permissionns_check(permissions_of_quarantined_path_to_program):

    if not os.path.exists(permissions_of_quarantined_path_to_program):
        print(f"[!] WARNING: Path does not exist: {permissions_of_quarantined_path_to_program}.")
        message = f"[!] WARNING: Path does not exist: {permissions_of_quarantined_path_to_program}."
        logger(message)
        return

    stats_p = os.stat(permissions_of_quarantined_path_to_program)
    permissions_program = oct(stats_p.st_mode)[-3:]

    if permissions_program != "000":
        message = f"[i] Trying to apply permissions again: {permissions_of_quarantined_path_to_program} Current Permission: {permissions_program}"
        logger(message)
        os.chmod(permissions_of_quarantined_path_to_program, program_permissions)
        stats_p = os.stat(permissions_of_quarantined_path_to_program)
        permissions_program = oct(stats_p.st_mode)[-3:]

        if permissions_program != "000":
            print(f"[!] WARNINNG Program: {permissions_of_quarantined_path_to_program} Current Permission: {permissions_program}")
            message = f"[!] WARNINNG Program: {permissions_of_quarantined_path_to_program} Current Permission: {permissions_program}"
            logger(message)
            last_line_defense(permissions_of_quarantined_path_to_program)



    stats_q = os.stat(QUARANTINE)
    permissions_quarantine = oct(stats_q.st_mode)[-3:]

    if permissions_quarantine !="644":
        message = f"[i] Trying to apply permissions again: {QUARANTINE}"
        logger(message)
        os.chmod(QUARANTINE, directory_permissions)
        stats_q = os.stat(QUARANTINE)
        permissions_quarantine = oct(stats_q.st_mode)[-3:]

        if permissions_quarantine != "644":
            print(f"[!] WARNING Program: {QUARANTINE} Current Permission: {permissions_quarantine}")
            message = f"[!] WARNING Program: {QUARANTINE} Current Permission: {permissions_quarantine}"
            logger(message)
            last_line_defense(permissions_of_quarantined_path_to_program)

###############################################################################################################