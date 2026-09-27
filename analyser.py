import re
from collections import Counter, defaultdict

LOG_FILE = "sampleAuth.log"
REPORT_FILE = "report.txt"
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

report_lines = ["--- Log Analysis Report ---"]

for ip, count in failures_per_ip.most_common():
    tried = ", ".join(sorted(usernames_per_ip[ip]))
    if count >= THRESHOLD:
        report_lines.append(f"[ALERT] {ip} - {count} failed logins (possible brute force)")
        report_lines.append(f"        usernames tried: {tried}")
    else:
        report_lines.append(f"[ok]    {ip} - {count} failed logins (usernames tried: {tried})")

report_text = "\n".join(report_lines)

print(report_text)

with open(REPORT_FILE, "w") as f:
    f.write(report_text)

print(f"\nReport saved to {REPORT_FILE}")