import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Charger le fichier brute force (Tuesday)
path = 'data/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv'
print(f"Chargement de {path}...")
df = pd.read_csv(path, encoding='utf-8', low_memory=False)

# Nettoyer les noms de colonnes (enlever les espaces)
df.columns = df.columns.str.strip()

print(f"\n=== Informations générales ===")
print(f"Nombre de lignes : {len(df):,}")
print(f"Nombre de colonnes : {len(df.columns)}")

# Trouver la colonne label (peut s'appeler 'Label' ou 'label')
label_col = None
for col in df.columns:
    if col.lower() == 'label':
        label_col = col
        break

if label_col:
    print(f"\n=== Distribution des labels ===")
    print(df[label_col].value_counts())
    
    # Visualiser la distribution des classes
    plt.figure(figsize=(8,4))
    df[label_col].value_counts().plot(kind='bar', color=['steelblue','tomato'])
    plt.title('Distribution des classes - CICIDS2017 Tuesday')
    plt.xlabel('Label')
    plt.ylabel('Nombre de flux')
    plt.tight_layout()
    plt.savefig('data/cicids2017/class_distribution.png', dpi=150)
    print("\nGraphique sauvegardé dans data/cicids2017/class_distribution.png")
    plt.show()
else:
    print("Colonne 'Label' non trouvée")
    print("Premières colonnes :", df.columns[:10].tolist())