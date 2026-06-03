import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                              roc_auc_score, f1_score)
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
import joblib
import os

# ── Charger les données ────────────────────────────────────────────────────
df = pd.read_csv('data/generated_logs/training_dataset_layer2.csv')
feature_cols = ['req_per_min', 'failed_logins', 'login_success_ratio',
                'new_accounts', 'scan_score', 'listing_reqs',
                'error_ratio_4xx', 'ua_anomaly']
X = df[feature_cols].fillna(0)
y = df['label']

print(f"Dataset : {len(X)} échantillons, {X.shape[1]} features")
print(f"Distribution : {y.value_counts().to_dict()}")

# ── Train/Test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# ── SMOTE pour équilibrer les classes ──────────────────────────────────────
print("\nApplication de SMOTE...")
smote = SMOTE(random_state=42)
X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)
print(f"Après SMOTE : {y_train_sm.value_counts().to_dict()}")

# ── Normalisation (nécessaire pour SVM et KNN) ─────────────────────────────
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_sm)
X_test_scaled  = scaler.transform(X_test)
joblib.dump(scaler, 'ml_models/saved_models/scaler_layer2.joblib')

# ── Définir les modèles ────────────────────────────────────────────────────
models = {
    'Random Forest' : RandomForestClassifier(n_estimators=100,
                        class_weight='balanced', random_state=42),
    'SVM'           : SVC(kernel='rbf', class_weight='balanced',
                        probability=True, random_state=42),
    'KNN'           : KNeighborsClassifier(n_neighbors=5),
    'Decision Tree' : DecisionTreeClassifier(max_depth=10,
                        class_weight='balanced', random_state=42),
}

results = {}

for name, model in models.items():
    print(f"\n{'='*50}")
    print(f"  {name}")
    print(f"{'='*50}")

    # Utiliser les données scalées pour SVM et KNN
    if name in ['SVM', 'KNN']:
        model.fit(X_train_scaled, y_train_sm)
        y_pred = model.predict(X_test_scaled)
        y_prob = model.predict_proba(X_test_scaled)[:,1] if hasattr(model, 'predict_proba') else y_pred
    else:
        model.fit(X_train_sm, y_train_sm)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:,1]

    f1  = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)

    print(classification_report(y_test, y_pred,
          target_names=['Bénin','Attaque'], zero_division=0))
    print(f"AUC-ROC : {auc:.4f}")
    print(f"Matrice de confusion :")
    print(confusion_matrix(y_test, y_pred))

    results[name] = {'f1': f1, 'auc': auc, 'model': model}

    # Sauvegarder le modèle
    safe_name = name.lower().replace(' ','_')
    joblib.dump(model, f'ml_models/saved_models/{safe_name}_layer2.joblib')

# ── Résumé comparatif ──────────────────────────────────────────────────────
print(f"\n{'='*50}")
print("  RÉSUMÉ COMPARATIF — COUCHE 2")
print(f"{'='*50}")
print(f"{'Modèle':<20} {'F1-Score':>10} {'AUC-ROC':>10}")
print('-' * 42)
for name, res in results.items():
    print(f"{name:<20} {res['f1']:>10.4f} {res['auc']:>10.4f}")

best = max(results, key=lambda k: results[k]['f1'])
print(f"\nMeilleur modèle : {best} (F1={results[best]['f1']:.4f})")