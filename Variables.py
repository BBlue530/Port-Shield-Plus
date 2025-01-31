from collections import defaultdict
from collections import deque

PORTS_ACCESSED = 5

BLOCK_DURATION = 30 # can make perma but need it short for testing

VIRUSTOTAL_API_KEY = "c716690d041318f1879c8b93c2815ce2b7c02609aada6ac18e0bfe0996890c29" # I know its bad to have the api key hardcoded like this but fuck it

HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

RATE_LIMIT = 3

QUARANTINE = "/Quarantine"

BACKUP_FILES ="/Backup"

BACKUP_KEY = "backup_key.key"

requests_made = deque()

ip_ports_accessed = defaultdict(set)

log_file = "Port_Shield.txt"

old_seen_programs = set()

owner_email = "bb3250577@gmail.com"