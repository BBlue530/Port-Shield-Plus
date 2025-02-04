import os
import time
import platform
from Variables import BLOCK_DURATION
from IPLogger import logger

ip_last_blocked = {}

def block_ip(ip):
    current_time = time.time()
    if ip in ip_last_blocked and current_time - ip_last_blocked[ip] < BLOCK_DURATION:
        print(f"[i] IP {ip} already blocked recently.")
        return

    current_os = platform.system().lower()

    if current_os == 'linux':
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        message = f"[i] Block IP: {ip} for: {BLOCK_DURATION} seconds."
        logger(message)
    elif current_os == 'windows':
        os.system(f"netsh advfirewall firewall add rule name='Block {ip}' dir=in interface=any action=block remoteip={ip}")
        message = f"[i] Block IP: {ip} for: {BLOCK_DURATION} seconds."
        logger(message)

    ip_last_blocked[ip] = current_time


    # VVV Comment these lines out for block to be perma VVV
    time.sleep(BLOCK_DURATION)

    if current_os == 'linux':
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    elif current_os == 'windows':
        os.system(f"netsh advfirewall firewall delete rule name='Block {ip}'")

    message = f"[i] Unblock IP: {ip} after: {BLOCK_DURATION} seconds."
    logger(message)