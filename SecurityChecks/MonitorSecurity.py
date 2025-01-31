from Variables import QUARANTINE
from IPLogger import logger
from SecurityChecks.NuclearOption import last_line_defense

###############################################################################################################

def check_quarantine_integrity(current_hash, stored_hash, path_to_program):
    if current_hash != stored_hash:
        print(f"[ALERT] Integrity check failed for {current_hash}.")
        message = f"[ALERT] Integrity check failed for {current_hash}."
        logger(message)
        last_line_defense(path_to_program)

###############################################################################################################