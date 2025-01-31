import datetime
from Variables import log_file

def logger(message):
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - {message}\n"

    with open(log_file, "a") as log:
        log.write(log_message)