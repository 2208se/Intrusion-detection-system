"""
Couche 2 — Analyse des journaux applicatifs
Parse les logs Apache et extrait des features comportementales
par IP sur des fenêtres glissantes de 5 minutes.
"""
import re
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Expression régulière pour parser une ligne de log Apache
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<endpoint>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d+) - "(?P<ua>[^"]*)"'
)

def parse_log_file(log_path):
    """Parse le fichier de logs et retourne une liste de dictionnaires."""
    entries = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if m:
                try:
                    ts = datetime.strptime(
                        m.group('time'), '%d/%b/%Y:%H:%M:%S +0000')
                    entries.append({
                        'ip'      : m.group('ip'),
                        'time'    : ts,
                        'method'  : m.group('method'),
                        'endpoint': m.group('endpoint'),
                        'status'  : int(m.group('status')),
                        'ua'      : m.group('ua'),
                    })
                except:
                    continue
    return entries

SUSPICIOUS_UAS = ['hydra', 'nikto', 'sqlmap', 'nmap', 'masscan',
                  'zgrab', 'python-requests', 'go-http-client']

def ua_score(ua_string):
    ua_lower = ua_string.lower()
    return 1 if any(s in ua_lower for s in SUSPICIOUS_UAS) else 0

def extract_features(entries, window_minutes=5):
    """
    Agrège les entrées de logs par IP et par fenêtre de 5 minutes.
    Retourne un DataFrame avec les features comportementales.
    """
    if not entries:
        return pd.DataFrame()

    df = pd.DataFrame(entries)
    df = df.sort_values('time')
    df['window'] = df['time'].dt.floor(f'{window_minutes}min')

    records = []
    for (ip, window), group in df.groupby(['ip', 'window']):
        total_req    = len(group)
        
        # MODIFICATION: Capture BOTH /api/auth/login AND /api/auth/login-form
        failed_logins = len(group[
            (group['endpoint'].str.contains('/api/auth/login')) & 
            (group['status'] == 401)
        ])
        
        success_logins = len(group[
            (group['endpoint'].str.contains('/api/auth/login')) & 
            (group['status'] == 200)
        ])
        
        new_accounts = len(group[
            (group['endpoint'] == '/api/auth/register') & 
            (group['status'] == 201)
        ])
        
        scan_score   = len(group[group['status'] == 404])
        listing_reqs = len(group[group['endpoint'].str.startswith('/api/listings')])
        errors_4xx   = len(group[group['status'].between(400, 499)])
        ua_anomaly   = group['ua'].apply(ua_score).max()

        login_ratio = (success_logins / (success_logins + failed_logins)
                       if (success_logins + failed_logins) > 0 else 1.0)

        records.append({
            'ip'              : ip,
            'window'          : window,
            'req_per_min'     : total_req / window_minutes,
            'failed_logins'   : failed_logins,
            'login_success_ratio': login_ratio,
            'new_accounts'    : new_accounts,
            'scan_score'      : scan_score,
            'listing_reqs'    : listing_reqs,
            'error_ratio_4xx' : errors_4xx / total_req if total_req > 0 else 0,
            'ua_anomaly'      : ua_anomaly,
        })
    return pd.DataFrame(records)

if __name__ == '__main__':
    import sys
    log_path = sys.argv[1] if len(sys.argv) > 1 else 'data/generated_logs/access.log'
    print(f"Parsing : {log_path}")
    entries = parse_log_file(log_path)
    print(f"Entrées parsées : {len(entries)}")
    features = extract_features(entries)
    print(f"Fenêtres extraites : {len(features)}")
    print(features.head(10).to_string())
    features.to_csv('data/generated_logs/features_layer2.csv', index=False)
    print("Features sauvegardées : data/generated_logs/features_layer2.csv")