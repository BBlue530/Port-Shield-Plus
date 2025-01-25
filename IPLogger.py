import datetime
from Variables import log_file

def logger(message, ip, packet_type="TCP"):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, 'a') as log:
            log.write(f"{timestamp} - {message} - {packet_type} - {ip}\n")
    except Exception as e:
        print(f"Error: {e}")