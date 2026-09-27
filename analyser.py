import re

LOG_FILE = "sampleAuth.log"

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

with open(LOG_FILE) as f:
    for line in f:
        match = FAILED_PATTERN.search(line)
        if match:
            username, ip = match.groups()
            print(f"Failed login: user={username} ip={ip}")