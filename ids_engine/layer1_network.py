"""
Couche 1 — Analyse du trafic réseau
Capture les paquets avec Scapy et extrait des features réseau
par IP sur des fenêtres de 60 secondes.
"""
from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
from datetime import datetime
import pandas as pd
import threading
import time

# Stockage des paquets par IP
packet_store = defaultdict(list)
lock = threading.Lock()

SUSPICIOUS_UAS = ['hydra','nikto','sqlmap','nmap','masscan',
                  'python-requests','go-http-client','zgrab']

def process_packet(pkt):
    """Callback appelé pour chaque paquet capturé."""
    if IP not in pkt:
        return
    src_ip = pkt[IP].src
    with lock:
        packet_store[src_ip].append({
            'time'    : time.time(),
            'size'    : len(pkt),
            'has_tcp' : TCP in pkt,
            'has_udp' : UDP in pkt,
            'dst_port': pkt[TCP].dport if TCP in pkt else (
                        pkt[UDP].dport if UDP in pkt else 0),
            'src_port': pkt[TCP].sport if TCP in pkt else 0,
            'payload' : bytes(pkt[Raw]).decode('utf-8','ignore')
                        if Raw in pkt else '',
        })

def extract_network_features(window_seconds=60):
    """Extrait des features réseau par IP sur la fenêtre passée."""
    now = time.time()
    cutoff = now - window_seconds
    records = []

    with lock:
        for ip, pkts in packet_store.items():
            recent = [p for p in pkts if p['time'] >= cutoff]
            if not recent:
                continue

            total       = len(recent)
            duration    = max(recent[-1]['time'] - recent[0]['time'], 1)
            req_rate    = total / (duration / 60)
            avg_size    = sum(p['size'] for p in recent) / total
            dst_ports   = set(p['dst_port'] for p in recent)
            src_ports   = set(p['src_port'] for p in recent)
            payloads    = ' '.join(p['payload'] for p in recent).lower()
            ua_anomaly  = 1 if any(s in payloads for s in SUSPICIOUS_UAS) else 0

            # Compter les codes HTTP depuis le payload (approximatif)
            error_count = payloads.count(' 401 ') + payloads.count(' 404 ')
            error_ratio = error_count / total if total > 0 else 0

            records.append({
                'ip'           : ip,
                'req_rate'     : req_rate,
                'payload_size' : avg_size,
                'unique_ports' : len(dst_ports),
                'src_port_variety': len(src_ports),
                'error_ratio'  : error_ratio,
                'ua_anomaly'   : ua_anomaly,
                'total_packets': total,
            })

    return pd.DataFrame(records)

def start_capture(interface=None, duration=None):
    """Démarre la capture. interface=None = capture sur toutes les interfaces."""
    print(f"Capture démarrée sur l'interface : {interface or 'toutes'}")
    print("Ctrl+C pour arrêter.")
    try:
        sniff(iface=interface,
              prn=process_packet,
              store=False,
              timeout=duration,
              filter="tcp port 5000")
    except KeyboardInterrupt:
        print("\nCapture arrêtée.")

if __name__ == '__main__':
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    # Capture pendant 60 secondes, puis affiche les features
    capture_thread = threading.Thread(target=start_capture,
                                       args=(iface, 60))
    capture_thread.start()
    capture_thread.join()
    features = extract_network_features()
    print(f"\nIPs détectées : {len(features)}")
    print(features.to_string())
    features.to_csv('data/lab_captures/network_features.csv', index=False)