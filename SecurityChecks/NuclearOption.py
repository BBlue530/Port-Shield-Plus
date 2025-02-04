import subprocess
from cryptography.fernet import Fernet
import os
import socket
from IPLogger import logger
from ProgramMonitoring.Immutable import remove_immutable
from Variables import BACKUP_FILES, BACKUP_KEY, owner_email

###############################################################################################################

def last_line_defense(program):
    print(f"[!] LAST LINE OF DEFENSE TRIGGERED: CAUSE: {program}")
    message = f"[!] LAST LINE OF DEFENSE TRIGGERED: CAUSE: {program}"
    logger(message)
    from ProgramMonitoring.HandleBadProgram import kill_program
    encrypt_backup_files(BACKUP_KEY)
    remove_compromised_program(program)
    alert_owner(owner_email)
    kill_program(program)
    disable_network()
    lockdown_bios()

###############################################################################################################

def encrypt_backup_files(BACKUP_KEY):
    if BACKUP_KEY is None:
        print("[!] ERROR Backup key is missing!")
        message = "[!] ERROR Backup key is missing!"
        logger(message)
        return

    cipher = Fernet(BACKUP_KEY)
    try:
        for root, _, files in os.walk(BACKUP_FILES):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = cipher.encrypt(data)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                print(f"[i] Encrypted backup file: {file_path}")
                message = f"[i] Encrypted backup file: {file_path}"
                logger(message)
    except Exception as e:
        print(f"[!] ERROR encrypting backup files: {e}")
        message = f"[!] ERROR encrypting backup files: {e}"
        logger(message)

def load_BACKUP_KEY():
    try:
        with open(BACKUP_KEY, "rb") as key_file:
            return key_file.read()
    except Exception as e:
        print(f"[!] ERROR loading backup encryption key: {e}")
        message = f"[!] ERROR loading backup encryption key: {e}"
        logger(message)
        return None

BACKUP_KEY = load_BACKUP_KEY()

###############################################################################################################

def remove_compromised_program(program):
    try:
        remove_immutable(program)
        os.remove(program)
        print(f"[i] Removed program: {program}")
        message = f"[i] Removed program: {program}"
        logger(message)
    except Exception as e:
        print(f"[!] WARNING Failed to remove program {program}: {e}")
        message = f"[!] WARNING Failed to remove program {program}: {e}"
        logger(message)

###############################################################################################################

def alert_owner(owner_email):
    hostname, ip_address = machine_info()
    
    email_message = f"""
    [SECURITY ALERT] Suspicious Activity Detected On:
    Machine Name: {hostname}
    IP Address: {ip_address}
    """

    try:
        subprocess.run(["mail", "-s", "Security Alert", owner_email], input=email_message.encode(), check=True)
        print(f"[i] Notified: {owner_email} with alert.")
        message = f"[i] Notified: {owner_email} with alert."
        logger(message)
    except Exception as e:
        print(f"[!] WARNING Failed to notify owner: {e}")
        message = f"[!] WARNING Failed to notify owner: {e}"
        logger(message)

def machine_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return hostname, ip_address
    except Exception as e:
        print(f"[!] WARNING Failed getting machine info: {e}")
        message = f"[!] WARNING Failed getting machine info: {e}"
        logger(message)
        return "Unknown", "Unknown"

###############################################################################################################

def disable_network():
    try:
        subprocess.run(["ip", "link", "set", "down", "eth0"], check=True)
        subprocess.run(["ip", "link", "set", "down", "wlan0"], check=True)
        print("[i] Network interfaces disabled.")
        message = "[i] Network interfaces disabled."
        logger(message)
    except Exception as e:
        print(f"[!] WARNING Failed disable network: {e}")
        message = f"[!] WARNING Failed disable network: {e}"
        logger(message)

###############################################################################################################

def lockdown_bios():
    try:
        subprocess.run(["systemctl", "reboot", "--firmware-setup"], check=True)
        print("[i] Rebooting into BIOS.")
        message = "[i] Rebooting into BIOS."
        logger(message)
    except Exception as e:
        print(f"[!] WARNING Failed reboot into BIOS: {e}")
        message = f"[!] WARNING Failed reboot into BIOS: {e}"
        logger(message)

###############################################################################################################