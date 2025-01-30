import datetime
from Variables import log_file

def logger(message, ip, packet_type="TCP"):
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message} - {packet_type} - {ip}\n"

    with open(log_file, "a") as log:
        log.write(log_entry)