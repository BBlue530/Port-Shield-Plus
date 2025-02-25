from collections import defaultdict
from collections import deque

PORTS_ACCESSED = 5

BLOCK_DURATION = 30 # can make perma but need it short for testing

QUARANTINE = "/Quarantine"

BACKUP_FILES ="/Backup"

BACKUP_KEY = "backup_key.key"

program_permissions = 0o644
directory_permissions = 0o000

ip_ports_accessed = defaultdict(set)

log_file = "Port_Shield.txt"

old_seen_programs = set()

owner_email = "bb3250577@gmail.com"