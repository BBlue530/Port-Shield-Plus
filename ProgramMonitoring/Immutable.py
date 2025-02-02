import subprocess
from Variables import QUARANTINE
from IPLogger import logger

###############################################################################################################

def remove_immutable(quarantined_path_to_program):
    try:
        subprocess.call(['chattr', '-i', quarantined_path_to_program])
        message = f"Removed immutable from: {quarantined_path_to_program}"
        logger(message)
    except Exception as e:
        print(f"[!] WARNING ERROR REMOVING IMMUTABLE: {quarantined_path_to_program}: {e}")
        message = f"[!] WARNING ERROR REMOVING IMMUTABLE: {quarantined_path_to_program}: {e}"
        logger(message)



def apply_immutable(quarantined_path_to_program):
    try:
        subprocess.call(['chattr', '+i', quarantined_path_to_program])
        message = f"applied immutable to: {quarantined_path_to_program}"
        logger(message)
    except Exception as e:
        print(f"[!] WARNING ERROR APPLYING IMMUTABLE: {quarantined_path_to_program}: {e}")
        message = f"[!] WARNING ERROR APPLYING IMMUTABLE: {quarantined_path_to_program}: {e}"
        logger(message)

###############################################################################################################

def apply_directory_immutable(QUARANTINE):
    try:
        subprocess.call(['chattr', '+Ri', QUARANTINE])
        message = f"applied immutable to: {QUARANTINE}"
        logger(message)
    except Exception as e:
        print(f"[!] WARNING ERROR APPLYING IMMUTABLE: {QUARANTINE}: {e}")
        message = f"[!] WARNING ERROR APPLYING IMMUTABLE: {QUARANTINE}: {e}"
        logger(message)



def remove_directory_immutable(QUARANTINE):
    try:
        subprocess.call(['chattr', '-Ri', QUARANTINE])
        message = f"Removed immutable from: {QUARANTINE}"
        logger(message)
    except Exception as e:
        print(f"[!] WARNING ERROR REMOVING IMMUTABLE: {QUARANTINE}: {e}")
        message = f"[!] WARNING ERROR REMOVING IMMUTABLE: {QUARANTINE}: {e}"
        logger(message)

###############################################################################################################