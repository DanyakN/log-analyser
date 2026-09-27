import re
from collections import Counter

LOG_FILE = "sampleAuth.log"
THRESHOLD = 5 

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

failures_per_ip = Counter()

with open(LOG_FILE) as f:
    for line in f:
        match = FAILED_PATTERN.search(line)
        if match:
            username, ip = match.groups()
            failures_per_ip[ip] += 1

print("--- Log Analysis Report ---")
for ip, count in failures_per_ip.most_common():
    if count >= THRESHOLD:
        print(f"[ALERT] {ip} - {count} failed logins (possible brute force)")
    else:
        print(f"[ok]    {ip} - {count} failed logins")