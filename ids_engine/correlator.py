"""
Moteur de corrélation — Couche 3
Croise les alertes de la Couche 1 (réseau) et Couche 2 (logs)
pour produire un score de risque final par IP.
Version continue : analyse toutes les X secondes.
"""


import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from ids_engine.layer2_logs import parse_log_file, extract_features

# ── Charger les modèles sauvegardés ───────────────────────────────────────
def load_models():
    models = {}
    for layer in [2]:  # layer 1 nécessite capture live
        for name in ['random_forest','decision_tree','knn','svm']:
            path = f'ml_models/saved_models/{name}_layer{layer}.joblib'
            try:
                models[f'{name}_l{layer}'] = joblib.load(path)
            except:
                pass
    scaler_l2 = joblib.load('ml_models/saved_models/scaler_layer2.joblib')
    return models, scaler_l2

# ── Prédiction Couche 2 ───────────────────────────────────────────────────
FEAT_COLS_L2 = ['req_per_min','failed_logins','login_success_ratio',
                'new_accounts','scan_score','listing_reqs',
                'error_ratio_4xx','ua_anomaly']

def predict_layer2(log_path, models, scaler):
    entries  = parse_log_file(log_path)
    features = extract_features(entries)
    if features.empty:
        return pd.DataFrame()

    X = features[FEAT_COLS_L2].fillna(0)
    X_scaled = scaler.transform(X)

    # Utiliser Random Forest comme modèle principal
    rf = models.get('random_forest_l2')
    if rf is None:
        return pd.DataFrame()

    proba = rf.predict_proba(X)[:,1]
    features['risk_score_l2'] = proba
    features['alert_l2']      = (proba > 0.5).astype(int)
    return features[['ip','window','risk_score_l2','alert_l2',
                     'failed_logins','req_per_min','scan_score',
                     'new_accounts','ua_anomaly']]

# ── Corrélation finale ────────────────────────────────────────────────────
def correlate_and_score(l2_results, l1_alerts=None):
    """
    Combine les scores des couches et produit une alerte finale.
    l1_alerts : dict {ip: risk_score} depuis la capture réseau (optionnel)
    """
    alerts = []
    for _, row in l2_results.iterrows():
        ip = row['ip']
        score_l2 = row['risk_score_l2']
        score_l1 = l1_alerts.get(ip, 0.0) if l1_alerts else 0.0

        # Score combiné : pondération 60% logs + 40% réseau
        combined = 0.6 * score_l2 + 0.4 * score_l1

        # Détecter le type d'attaque probable
        attack_type = 'Inconnu'
        if row['failed_logins'] > 10:
            attack_type = 'Brute Force / Credential Stuffing'
        elif row['scan_score'] > 5:
            attack_type = 'Reconnaissance / Scan'
        elif row['req_per_min'] > 50:
            attack_type = 'Scraping / DoS'
        elif row['new_accounts'] > 5:
            attack_type = 'Création de faux comptes'
        elif row['ua_anomaly'] == 1:
            attack_type = 'Agent suspect détecté'

        # Seuils pour le niveau d'alerte
        level = 'CRITIQUE' if combined > 0.7 else \
                'ÉLEVÉ'    if combined > 0.5 else \
                'MOYEN'    if combined > 0.3 else 'FAIBLE'

        alerts.append({
            'timestamp'    : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip'           : ip,
            'score_l2'     : round(score_l2, 3),
            'score_l1'     : round(score_l1, 3),
            'score_final'  : round(combined, 3),
            'niveau'       : level,
            'type_attaque' : attack_type,
            'alerte'       : 1 if combined > 0.3 else 0,
        })

    df = pd.DataFrame(alerts)
    if not df.empty:
        df = df.sort_values('score_final', ascending=False)
    return df

def run_analysis(log_path='data/generated_logs/access.log', quiet=False):
    """
    Exécute une analyse unique.
    Si quiet=True, n'affiche que les alertes (pas d'en-tête).
    """
    models, scaler = load_models()
    l2 = predict_layer2(log_path, models, scaler)
    if l2.empty:
        if not quiet:
            print("Aucune donnée à analyser.")
        return pd.DataFrame()
    
    results = correlate_and_score(l2)
    alerts = results[results['alerte'] == 1]
    
    if not quiet:
        print(f"\n{'='*60}")
        print(f"  RÉSULTATS D'ANALYSE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        print(f"IPs analysées   : {len(results)}")
        print(f"Alertes levées  : {len(alerts)}")
    
    if not alerts.empty:
        if not quiet:
            print(f"\nAlertes :")
        for _, a in alerts.iterrows():
            if not quiet:
                print(f"  [{a['niveau']}] {a['ip']} — {a['type_attaque']} "
                      f"(score={a['score_final']})")
    
    results.to_csv('data/generated_logs/correlation_results.csv', index=False)
    return results

# ── MODE CONTINU (LOOP) ────────────────────────────────────────────────────
def run_continuous(interval_seconds=10, log_path='data/generated_logs/access.log'):
    """
    Mode continu : analyse les logs toutes les X secondes.
    """
    print("="*60)
    print("  🛡️  IDS CORRELATOR - MODE CONTINU  🛡️")
    print("="*60)
    print(f"  📁 Logs : {log_path}")
    print(f"  ⏱️  Intervalle : {interval_seconds} secondes")
    print("  🛑 CTRL+C pour arrêter")
    print("="*60)
    print()
    
    # Compteur pour le nombre d'analyses
    analysis_count = 0
    
    try:
        while True:
            analysis_count += 1
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"\n[{current_time}] 🔄 Analyse #{analysis_count}")
            print("-" * 40)
            
            run_analysis(log_path, quiet=False)
            
            print(f"\n⏳ Prochaine analyse dans {interval_seconds} secondes...")
            time.sleep(interval_seconds)
            
    except KeyboardInterrupt:
        print("\n\n" + "="*60)
        print(f"  👋 Corrélateur arrêté après {analysis_count} analyses.")
        print("="*60)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='IDS Correlator')
    parser.add_argument('--once', action='store_true', 
                        help='Exécuter une seule analyse (pas de boucle)')
    parser.add_argument('--interval', type=int, default=10,
                        help='Intervalle entre les analyses en secondes (défaut: 10)')
    parser.add_argument('--log', type=str, default='data/generated_logs/access.log',
                        help='Chemin du fichier de logs')
    
    args = parser.parse_args()
    
    if args.once:
        # Mode unique
        run_analysis(args.log)
    else:
        # Mode continu (par défaut)
        run_continuous(interval_seconds=args.interval, log_path=args.log)