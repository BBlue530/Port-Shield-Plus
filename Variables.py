from collections import defaultdict

PORTS_ACCESSED = 5

BLOCK_DURATION = 30 # can make perma but need it short for testing

ip_ports_accessed = defaultdict(set)

log_file = "Port_Shield.log"