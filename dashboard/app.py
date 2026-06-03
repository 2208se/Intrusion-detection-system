"""
Dashboard Administrateur — IDS Vinted Algeria
Tableau de bord Streamlit pour visualiser les alertes et métriques.
"""
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

st.set_page_config(
    page_title="IDS — Vinted Algeria",
    page_icon="🛡️",
    layout="wide"
)

# ── CSS personnalisé ──────────────────────────────────────────────────────
st.markdown("""
<style>
.alert-critique { background:#fde8e8; border-left:4px solid #e53e3e;
                  padding:10px; margin:5px 0; border-radius:4px; }
.alert-eleve    { background:#fef3cd; border-left:4px solid #f6ad55;
                  padding:10px; margin:5px 0; border-radius:4px; }
.alert-moyen    { background:#e8f4fd; border-left:4px solid #4299e1;
                  padding:10px; margin:5px 0; border-radius:4px; }
.metric-card    { background:#f7fafc; border:1px solid #e2e8f0;
                  padding:15px; border-radius:8px; text-align:center; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ IDS — SOUKDZ ")
st.caption(f"Système de Détection d'Intrusion | Mis à jour : "
           f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# ── Sidebar ───────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Configuration")
log_path = st.sidebar.text_input(
    "Chemin du fichier de logs",
    value="data/generated_logs/access.log"
)
refresh = st.sidebar.slider("Rafraîchissement (s)", 5, 60, 15)
threshold = st.sidebar.slider("Seuil d'alerte", 0.1, 0.9, 0.4)

# ── Onglets ───────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "🚨 Alertes en direct",
    "📊 Comparaison des modèles",
    "📈 Statistiques",
    "🗂️ Résultats de validation"
])

# ────────────────────────────────────────────────────────────────────────────
with tab1:
    st.subheader("Flux d'alertes en temps réel")

    if os.path.exists('data/generated_logs/correlation_results.csv'):
        df_alerts = pd.read_csv('data/generated_logs/correlation_results.csv')
        active = df_alerts[df_alerts['score_final'] >= threshold]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("IPs analysées",  len(df_alerts))
        col2.metric("Alertes actives", len(active),
                    delta=f"+{len(active[active['niveau']=='CRITIQUE'])}")
        col3.metric("Score max",
                    f"{df_alerts['score_final'].max():.2f}")
        col4.metric("Niveau critique",
                    len(active[active['niveau']=='CRITIQUE']))

        st.markdown("---")

        if active.empty:
            st.success("✅ Aucune activité suspecte détectée.")
        else:
            for _, row in active.iterrows():
                niveau = row.get('niveau', 'MOYEN')
                css_class = {
                    'CRITIQUE': 'alert-critique',
                    'ÉLEVÉ'   : 'alert-eleve',
                    'MOYEN'   : 'alert-moyen'
                }.get(niveau, 'alert-moyen')

                st.markdown(f"""
                <div class="{css_class}">
                  <b>[{niveau}]</b> IP : <code>{row['ip']}</code> |
                  Score : <b>{row['score_final']:.3f}</b> |
                  Type : {row.get('type_attaque','—')} |
                  {row.get('timestamp','')}
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("Tableau complet")
        st.dataframe(df_alerts.sort_values('score_final', ascending=False),
                     use_container_width=True)
    else:
        st.warning("Aucune analyse disponible. Lance d'abord :")
        st.code("python ids_engine/correlator.py")

# ────────────────────────────────────────────────────────────────────────────
with tab2:
    st.subheader("Comparaison des 4 algorithmes ML")

    for layer_num in [1, 2]:
        layer_label = {1: "Couche 1 — Réseau (CICIDS2017)",
                       2: "Couche 2 — Logs applicatifs"}[layer_num]
        st.markdown(f"#### {layer_label}")

        img_cm  = f'data/plots/confusion_matrices_layer{layer_num}.png'
        img_roc = f'data/plots/roc_curves_layer{layer_num}.png'

        col_a, col_b = st.columns(2)
        if os.path.exists(img_cm):
            col_a.image(img_cm, caption="Matrices de confusion")
        else:
            col_a.warning(f"Lance : python ml_models/generate_plots.py")

        if os.path.exists(img_roc):
            col_b.image(img_roc, caption="Courbes ROC")
        else:
            col_b.warning("Graphique non disponible")

        st.markdown("---")

# ────────────────────────────────────────────────────────────────────────────
with tab3:
    st.subheader("Statistiques des logs")

    if os.path.exists(log_path):
        try:
            sys.path.insert(0, '.')
            from ids_engine.layer2_logs import parse_log_file, extract_features
            entries  = parse_log_file(log_path)
            features = extract_features(entries)

            if not features.empty:
                st.metric("Entrées de log analysées", len(entries))
                st.metric("Fenêtres temporelles",     len(features))

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Top 10 IPs par volume de requêtes**")
                    top_ips = features.nlargest(10, 'req_per_min')[
                        ['ip','req_per_min','failed_logins','scan_score']]
                    st.dataframe(top_ips, use_container_width=True)

                with col2:
                    st.markdown("**Distribution des scores d'anomalie UA**")
                    fig, ax = plt.subplots(figsize=(5,3))
                    features['ua_anomaly'].value_counts().plot(
                        kind='bar', ax=ax,
                        color=['steelblue','tomato'],
                        tick_label=['Normal','Suspect'])
                    ax.set_title('User-Agent Anomaly')
                    plt.tight_layout()
                    st.pyplot(fig)
        except Exception as e:
            st.error(f"Erreur d'analyse : {e}")
    else:
        st.warning(f"Fichier de logs non trouvé : {log_path}")

# ────────────────────────────────────────────────────────────────────────────
with tab4:
    st.subheader("Résultats de la campagne de validation")

    if os.path.exists('data/validation_results.csv'):
        df_val = pd.read_csv('data/validation_results.csv')
        st.success("✅ Campagne de validation complète")
        st.dataframe(df_val, use_container_width=True)

        # Tableau de synthèse visuel
        fig, ax = plt.subplots(figsize=(8,3))
        detected = (df_val['Détecté'] == 'OUI').sum()
        not_det  = (df_val['Détecté'] == 'NON').sum()
        ax.bar(['Détectées', 'Non détectées'],
               [detected, not_det],
               color=['steelblue','tomato'])
        ax.set_title('Résultats de détection par scénario')
        ax.set_ylabel("Nombre de scénarios")
        plt.tight_layout()
        st.pyplot(fig)
    else:
        st.info("Lance d'abord la campagne de validation (Lab 9).")
        st.code("python attack_scripts/run_validation.py")

# ── Rafraîchissement automatique ──────────────────────────────────────────
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Relancer l'analyse maintenant"):
    with st.spinner("Analyse en cours..."):
        os.system("python ids_engine/correlator.py")
    st.rerun()