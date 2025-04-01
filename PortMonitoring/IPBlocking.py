import os
import time
from Variables import BLOCK_DURATION
from IPLogger import logger

ip_last_blocked = {}

def block_ip(ip):
    current_time = time.time()
    if ip in ip_last_blocked and current_time - ip_last_blocked[ip] < BLOCK_DURATION:
        print(f"[i] IP {ip} already blocked recently.")
        return

    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    message = f"[i] Block IP: {ip} for: {BLOCK_DURATION} seconds."
    logger(message)

    ip_last_blocked[ip] = current_time


    # VVV Comment these lines out for block to be perma VVV
    time.sleep(BLOCK_DURATION)
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    message = f"[i] Unblock IP: {ip} after: {BLOCK_DURATION} seconds."
    logger(message)