import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (confusion_matrix, roc_curve,
                              auc, classification_report, f1_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib, os

os.makedirs('data/plots', exist_ok=True)

MODEL_NAMES = ['random_forest', 'svm', 'knn', 'decision_tree']
DISPLAY_NAMES = ['Random Forest', 'SVM', 'KNN', 'Decision Tree']

def load_layer2_data():
    df = pd.read_csv('data/generated_logs/training_dataset_layer2.csv')
    feat = ['req_per_min','failed_logins','login_success_ratio',
            'new_accounts','scan_score','listing_reqs',
            'error_ratio_4xx','ua_anomaly']
    X = df[feat].fillna(0)
    y = df['label']
    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

def plot_confusion_matrices(layer, X_test, y_test):
    fig, axes = plt.subplots(1, 4, figsize=(20, 4))
    fig.suptitle(f'Matrices de Confusion — Couche {layer}', fontsize=14, y=1.02)
    scaler = joblib.load(f'ml_models/saved_models/scaler_layer{layer}.joblib')
    X_test_s = scaler.transform(X_test)

    for ax, name, dname in zip(axes, MODEL_NAMES, DISPLAY_NAMES):
        path = f'ml_models/saved_models/{name}_layer{layer}.joblib'
        if not os.path.exists(path):
            ax.set_title(f'{dname}\n(non disponible)')
            continue
        model = joblib.load(path)
        if name in ['svm','knn']:
            y_pred = model.predict(X_test_s)
        else:
            y_pred = model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['Bénin','Attaque'],
                    yticklabels=['Bénin','Attaque'])
        f1 = f1_score(y_test, y_pred, zero_division=0)
        ax.set_title(f'{dname}\nF1={f1:.3f}')
        ax.set_xlabel('Prédit')
        ax.set_ylabel('Réel')

    plt.tight_layout()
    plt.savefig(f'data/plots/confusion_matrices_layer{layer}.png',
                dpi=150, bbox_inches='tight')
    plt.show()
    print(f"Sauvegardé : data/plots/confusion_matrices_layer{layer}.png")

def plot_roc_curves(layer, X_test, y_test):
    plt.figure(figsize=(8, 6))
    scaler = joblib.load(f'ml_models/saved_models/scaler_layer{layer}.joblib')
    X_test_s = scaler.transform(X_test)
    colors = ['steelblue','tomato','seagreen','darkorange']

    for (name, dname, color) in zip(MODEL_NAMES, DISPLAY_NAMES, colors):
        path = f'ml_models/saved_models/{name}_layer{layer}.joblib'
        if not os.path.exists(path):
            continue
        model = joblib.load(path)
        if name in ['svm','knn']:
            y_prob = model.predict_proba(X_test_s)[:,1]
        else:
            y_prob = model.predict_proba(X_test)[:,1]
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, color=color, lw=2,
                 label=f'{dname} (AUC={roc_auc:.3f})')

    plt.plot([0,1],[0,1],'k--', lw=1, label='Aléatoire')
    plt.xlabel('Taux de faux positifs')
    plt.ylabel('Taux de vrais positifs (Rappel)')
    plt.title(f'Courbes ROC — Couche {layer}')
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'data/plots/roc_curves_layer{layer}.png',
                dpi=150, bbox_inches='tight')
    plt.show()
    print(f"Sauvegardé : data/plots/roc_curves_layer{layer}.png")

# ── Générer pour la Couche 2 ───────────────────────────────────────────────
print("Génération des graphiques pour la Couche 2...")
X_train, X_test, y_train, y_test = load_layer2_data()
plot_confusion_matrices(2, X_test, y_test)
plot_roc_curves(2, X_test, y_test)
print("\nTous les graphiques sont dans data/plots/")