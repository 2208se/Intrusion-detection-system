import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                              roc_auc_score, f1_score)
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
import joblib, os

# ── Charger et combiner les fichiers CICIDS2017 nettoyés ──────────────────
dfs = []
for fname in ['tuesday_clean.csv', 'friday_ddos_clean.csv',
              'friday_portscan_clean.csv']:
    fpath = f'data/cicids2017/{fname}'
    if os.path.exists(fpath):
        df = pd.read_csv(fpath)
        dfs.append(df)
        print(f"Chargé : {fname} ({len(df):,} lignes)")

df = pd.concat(dfs, ignore_index=True)
print(f"\nTotal : {len(df):,} lignes")
print(f"Distribution : {df['label_binary'].value_counts().to_dict()}")

# ── Préparer les features ─────────────────────────────────────────────────
# Garder seulement des colonnes numériques, pas de NaN
df = df.fillna(0)
feature_cols = [c for c in df.columns if c != 'label_binary']

# Sous-échantillonner pour accélérer l'entraînement
# (CICIDS2017 est très grand — on garde 50,000 bénins + tous les attaquants)
benign  = df[df['label_binary']==0].sample(n=min(50000, (df['label_binary']==0).sum()),
                                            random_state=42)
attacks = df[df['label_binary']==1]
df_balanced = pd.concat([benign, attacks]).sample(frac=1, random_state=42)

X = df_balanced[feature_cols]
y = df_balanced['label_binary']
print(f"\nAprès sous-échantillonnage : {len(X):,} lignes")

# ── Train/Test split ──────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# ── Normalisation ─────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)
joblib.dump(scaler, 'ml_models/saved_models/scaler_layer1.joblib')

# ── Modèles ───────────────────────────────────────────────────────────────
models = {
    'Random Forest' : RandomForestClassifier(n_estimators=100,
                        n_jobs=-1, class_weight='balanced', random_state=42),
    'SVM'           : SVC(kernel='rbf', class_weight='balanced',
                        probability=True, random_state=42, max_iter=1000),
    'KNN'           : KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    'Decision Tree' : DecisionTreeClassifier(max_depth=15,
                        class_weight='balanced', random_state=42),
}

results = {}
for name, model in models.items():
    print(f"\n{'='*50}\n  {name}\n{'='*50}")
    if name in ['SVM','KNN']:
        model.fit(X_train_s, y_train)
        y_pred = model.predict(X_test_s)
        y_prob = model.predict_proba(X_test_s)[:,1]
    else:
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:,1]

    f1  = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    print(classification_report(y_test, y_pred,
          target_names=['Bénin','Attaque'], zero_division=0))
    print(f"AUC-ROC : {auc:.4f}")
    print(confusion_matrix(y_test, y_pred))
    results[name] = {'f1': f1, 'auc': auc}
    safe = name.lower().replace(' ','_')
    joblib.dump(model, f'ml_models/saved_models/{safe}_layer1.joblib')

print(f"\n{'='*50}")
print("  RÉSUMÉ COMPARATIF — COUCHE 1 (CICIDS2017)")
print(f"{'='*50}")
print(f"{'Modèle':<20} {'F1':>8} {'AUC':>8}")
print('-'*38)
for name, r in results.items():
    print(f"{name:<20} {r['f1']:>8.4f} {r['auc']:>8.4f}")