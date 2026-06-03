# ml_models/create_training_dataset.py
import sys
sys.path.insert(0, '.')
from ids_engine.layer2_logs import parse_log_file, extract_features
import pandas as pd

# Parser les logs d'attaque générés
entries = parse_log_file('data/generated_logs/attack_training.log')
features = extract_features(entries)

# Labelliser : IPs attaquantes connues
attacker_ips = {'10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'}
features['label'] = features['ip'].apply(
    lambda ip: 1 if ip in attacker_ips else 0
)

# Supprimer les colonnes non-features
X = features.drop(columns=['ip', 'window', 'label'])
y = features['label']

print(f"Total fenêtres : {len(features)}")
print(f"Bénignes (0)   : {(y==0).sum()}")
print(f"Attaques (1)   : {(y==1).sum()}")

features.to_csv('data/generated_logs/training_dataset_layer2.csv', index=False)
print("Dataset sauvegardé : data/generated_logs/training_dataset_layer2.csv")