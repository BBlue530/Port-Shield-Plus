import os
import psutil
import time
import signal
import subprocess
from Variables import QUARANTINE
from IPLogger import logger
from SecurityChecks.NuclearOption import last_line_defense
from ProgramMonitoring.Immutable import apply_immutable
from Variables import QUARANTINE

###############################################################################################################

def check_quarantine_integrity(current_hash, stored_hash, path_to_program):
    if current_hash != stored_hash:
        print(f"[!] WARNING Integrity check failed for {current_hash}.")
        message = f"[!] WARNING Integrity check failed for {current_hash}."
        logger(message)
        last_line_defense(path_to_program) # Need to make it try to get integrity check work and then if it doesnt LLD

def encryption_check(quarantined_path_to_program, stored_hash):
    from ProgramMonitoring.HandleBadProgram import calculate_file_hash
    encrypted_hash = calculate_file_hash(quarantined_path_to_program)
    if encrypted_hash == stored_hash:
        print(f"[!] WARNING ENCRYPTION FAILED: {quarantined_path_to_program}.")
        message = f"[!] WARNING ENCRYPTION FAILED: {quarantined_path_to_program}."
        logger(message)
        from ProgramMonitoring.HandleBadProgram import encrypt_file_failed
        encrypt_file_failed(quarantined_path_to_program)
        new_encrypted_hash = calculate_file_hash
        if new_encrypted_hash == stored_hash:
            print(f"[!] WARNING ENCRYPTION FAILED ON: {quarantined_path_to_program}")
            message = f"[!] WARNING ENCRYPTION FAILED ON: {quarantined_path_to_program}"
            logger(message)
            last_line_defense(quarantined_path_to_program)

    else:
        message = f"Encryption worked {quarantined_path_to_program}."
        logger(message)


def quarantine_check():
    for filename in os.listdir(QUARANTINE):
        file = os.path.join(QUARANTINE, filename)
        if file == QUARANTINE:
            continue
        
        if os.path.isfile(file):
            writable_access_check(file)

def writable_access_check(file):
    try:
        os.chmod(file, 0o000)
        apply_immutable(file)

        with open(file, "a"): 
            print(f"[!] WARNING: {file} IS WRITEABLE.")
            message = f"[!] WARNING: {file} IS WRITEABLE."
            logger(message)
            os.chmod(file, 0o000)
            apply_immutable(file)

            with open(file, "a"):
                print(f"[!] WARNING: {file} IS STILL WRITEABLE.")
                message = f"[!] WARNING: {file} IS STILL WRITEABLE."
                logger(message)
                last_line_defense(file)

    except IOError:
        message = f"Quarantine {file} is protected from writing."
        logger(message)

###############################################################################################################

def pid_still_running(pid, path_to_program):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        message = f"Terminated PID: {pid}"
        logger(message)
        
        time.sleep(5)
        if psutil.pid_exists(pid):
            message = f"PID: {pid} still running"
            logger(message)
            os.kill(pid, signal.SIGKILL)
            time.sleep(5)
            
        if psutil.pid_exists(pid):
            proc.suspend()
            time.sleep(1)
            proc.kill()
            message = f"Suspended/Killed PID: {pid}"
            logger(message)
        
        if psutil.pid_exists(pid):
            kill_parent_program(pid)
        
        if psutil.pid_exists(pid):
            message = f"Last Kill of PID attempt: {pid}"
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
        message = f"Kill of parent program PID: {parent_pid} from: {pid}."
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

def permissionns_check(quarantined_path_to_program):

    stats_p = os.stat(quarantined_path_to_program)
    permissions_program = oct(stats_p.st_mode)[-3:]

    if permissions_program != "000":
        message = f"Trying to apply permissions again: {quarantined_path_to_program} Current Permission: {permissions_program}"
        logger(message)
        os.chmod(quarantined_path_to_program, 0o000)
        stats_p = os.stat(quarantined_path_to_program)
        permissions_program = oct(stats_p.st_mode)[-3:]

        if permissions_program != "000":
            print(f"WARNINNG Program: {quarantined_path_to_program} Current Permission: {permissions_program}")
            message = f"WARNINNG Program: {quarantined_path_to_program} Current Permission: {permissions_program}"
            logger(message)
            last_line_defense(quarantined_path_to_program)



    stats_q = os.stat(QUARANTINE)
    permissions_quarantine = oct(stats_q.st_mode)[-3:]

    if permissions_quarantine !="333":
        message = f"Trying to apply permissions again: {QUARANTINE}"
        logger(message)
        os.chmod(QUARANTINE, 0o333)
        stats_q = os.stat(QUARANTINE)
        permissions_quarantine = oct(stats_q.st_mode)[-3:]

        if permissions_quarantine != "333":
            print(f"[!] WARNING Program: {QUARANTINE} Current Permission: {permissions_quarantine}")
            message = f"[!] WARNING Program: {QUARANTINE} Current Permission: {permissions_quarantine}"
            logger(message)
            last_line_defense(quarantined_path_to_program)

###############################################################################################################