import re
from collections import Counter, defaultdict

LOG_FILE = "sampleAuth.log"
THRESHOLD = 5  # this many failed logins from one IP = suspicious

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

failures_per_ip = Counter()
usernames_per_ip = defaultdict(set)

with open(LOG_FILE) as f:
    for line in f:
        match = FAILED_PATTERN.search(line)
        if match:
            username, ip = match.groups()
            failures_per_ip[ip] += 1
            usernames_per_ip[ip].add(username)

print("--- Log Analysis Report ---")
for ip, count in failures_per_ip.most_common():
    tried = ", ".join(sorted(usernames_per_ip[ip]))
    if count >= THRESHOLD:
        print(f"[ALERT] {ip} - {count} failed logins (possible brute force)")
        print(f"        usernames tried: {tried}")
    else:
        print(f"[ok]    {ip} - {count} failed logins (usernames tried: {tried})")