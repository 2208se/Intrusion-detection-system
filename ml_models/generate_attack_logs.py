import random
from datetime import datetime, timedelta
import os

output = 'data/generated_logs/attack_training.log'
lines = []
base_time = datetime(2026, 4, 4, 8, 0, 0)

def fmt_time(dt):
    return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

# IP addresses
normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
attacker_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']

# NORMAL TRAFFIC - 500 samples
print("Generating normal traffic...")
for _ in range(500):
    ip = random.choice(normal_ips)
    t = base_time + timedelta(seconds=random.randint(0, 3600))
    lines.append(f'{ip} - - [{fmt_time(t)}] "GET /api/listings HTTP/1.1" 200 - "Mozilla/5.0"')

# BRUTE FORCE ATTACKS - 500 samples (THIS IS THE KEY CHANGE)
print("Generating brute force attacks...")
for _ in range(500):
    ip = random.choice(attacker_ips)
    t = base_time + timedelta(seconds=random.randint(0, 3600))
    lines.append(f'{ip} - - [{fmt_time(t)}] "POST /api/auth/login HTTP/1.1" 401 - "hydra/9.0"')

# SCAN ATTACKS - 400 samples
print("Generating scan attacks...")
for _ in range(400):
    ip = random.choice(attacker_ips)
    t = base_time + timedelta(seconds=random.randint(0, 3600))
    lines.append(f'{ip} - - [{fmt_time(t)}] "GET /api/listings/99999 HTTP/1.1" 404 - "nikto/2.5"')

# FAKE ACCOUNTS - 300 samples
print("Generating fake accounts...")
for _ in range(300):
    ip = random.choice(attacker_ips)
    t = base_time + timedelta(seconds=random.randint(0, 3600))
    lines.append(f'{ip} - - [{fmt_time(t)}] "POST /api/auth/register HTTP/1.1" 201 - "python-requests"')

# Shuffle everything
random.shuffle(lines)

# Save to file
os.makedirs('data/generated_logs', exist_ok=True)
with open('data/generated_logs/attack_training.log', 'w') as f:
    f.write('\n'.join(lines))

print(f"Logs generated: {len(lines)} lines")
print(f"   - Normal: 500")
print(f"   - Brute force: 500")
print(f"   - Scans: 400")
print(f"   - Fake accounts: 300")
print(f"File: data/generated_logs/attack_training.log")