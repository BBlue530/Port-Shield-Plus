import subprocess
from Variables import QUARANTINE
from IPLogger import logger

###############################################################################################################

def remove_immutable(quarantined_path_to_program):
    try:
        subprocess.call(['chattr', '-i', quarantined_path_to_program])
        print(f"Removed immutable from: {quarantined_path_to_program}")
        logger(f"Removed immutable from: {quarantined_path_to_program}")
    except Exception as e:
        print(f"[WARNING] ERROR REMOVING IMMUTABLE: {quarantined_path_to_program}: {e}")
        logger(f"[WARNING] ERROR REMOVING IMMUTABLE: {quarantined_path_to_program}: {e}")



def apply_immutable(quarantined_path_to_program):
    try:
        subprocess.call(['chattr', '+i', quarantined_path_to_program])
        print(f"applied immutable to: {quarantined_path_to_program}")
        logger(f"applied immutable to: {quarantined_path_to_program}")
    except Exception as e:
        print(f"[WARNING] ERROR APPLYING IMMUTABLE: {quarantined_path_to_program}: {e}")
        logger(f"[WARNING] ERROR APPLYING IMMUTABLE: {quarantined_path_to_program}: {e}")

###############################################################################################################

def apply_directory_immutable(QUARANTINE):
    try:
        subprocess.call(['chattr', '+Ri', QUARANTINE])
        print(f"applied immutable to: {QUARANTINE}")
        logger(f"applied immutable to: {QUARANTINE}")
    except Exception as e:
        print(f"[WARNING] ERROR APPLYING IMMUTABLE: {QUARANTINE}: {e}")
        logger(f"[WARNING] ERROR APPLYING IMMUTABLE: {QUARANTINE}: {e}")



def remove_directory_immutable(QUARANTINE):
    try:
        subprocess.call(['chattr', '-Ri', QUARANTINE])
        print(f"Removed immutable from: {QUARANTINE}")
        logger(f"Removed immutable from: {QUARANTINE}")
    except Exception as e:
        print(f"[WARNING] ERROR REMOVING IMMUTABLE: {QUARANTINE}: {e}")
        logger(f"[WARNING] ERROR REMOVING IMMUTABLE: {QUARANTINE}: {e}")

###############################################################################################################

def ensure_immutable(quarantined_program):
        immutable_flag = subprocess.check_output(['lsattr', quarantined_program]).decode('utf-8')
        if 'i' not in immutable_flag:
            apply_immutable(quarantined_program)

###############################################################################################################