import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import os

def clean_cicids(filepath, output_path):
    print(f"Traitement de {filepath}...")
    df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
    df.columns = df.columns.str.strip()

    # Renommer la colonne label
    label_col = ' Label' if ' Label' in df.columns else 'Label'
    df = df.rename(columns={label_col: 'label'})

    # Supprimer les colonnes inutiles
    drop_cols = ['Flow ID', ' Source IP', ' Destination IP',
                 ' Source Port', ' Timestamp']
    df = df.drop(columns=[c for c in drop_cols if c in df.columns])

    # Remplacer valeurs infinies par NaN puis supprimer
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    print(f"  Lignes supprimées (NaN/inf) : {before - len(df):,}")

    # Encoder les labels : BENIGN=0, tout le reste=1
    df['label_binary'] = (df['label'] != 'BENIGN').astype(int)
    print(f"  Distribution binaire :")
    print(f"    Bénin (0)  : {(df['label_binary']==0).sum():,}")
    print(f"    Attaque (1): {(df['label_binary']==1).sum():,}")

    # Garder seulement les colonnes numériques
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df = df[num_cols + ['label_binary']]

    df.to_csv(output_path, index=False)
    print(f"  Sauvegardé : {output_path}")
    return df

# Traiter les 3 fichiers
files = [
    ('data/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv',
     'data/cicids2017/tuesday_clean.csv'),
    ('data/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
     'data/cicids2017/friday_ddos_clean.csv'),
    ('data/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
     'data/cicids2017/friday_portscan_clean.csv'),
]

for src, dst in files:
    if os.path.exists(src):
        clean_cicids(src, dst)
    else:
        print(f"Fichier non trouvé : {src}")

print("\nPréparation terminée.")