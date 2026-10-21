# dashboard/app.py
import sys
import os
import streamlit as st
import pandas as pd

# Ajout du répertoire racine au PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analysis_engine import analyze_pcap

st.set_page_config(
    page_title="Wi-Fi Threat Detection Platform",
    page_icon="📡",
    layout="wide"
)

st.title("📡 Wi-Fi Threat Detection & Analysis Platform")
st.markdown("Plateforme d'analyse et de détection d'attaques sur réseaux sans fil 802.11")

# Sidebar pour le chargement des fichiers
st.sidebar.header("📁 Sélection du Fichier PCAP")
raw_dir = "data/raw"

available_files = [f for f in os.listdir(raw_dir) if f.endswith(".pcap") or f.endswith(".pcapng")] if os.path.exists(raw_dir) else []

selected_file = st.sidebar.selectbox("Choisissez un fichier PCAP de test :", available_files)

if selected_file:
    pcap_path = os.path.join(raw_dir, selected_file)
    
    if st.sidebar.button("🚀 Lancer l'analyse", use_container_width=True):
        with st.spinner("Analyse du fichier PCAP en cours..."):
            results = analyze_pcap(pcap_path)

        # Affichage des métriques principales
        st.subheader("📊 Score de Risque & Niveau de Menace")
        col1, col2, col3 = st.columns(3)

        color_map = {
            "CRITIQUE": "🔴",
            "ÉLEVÉ": "🟠",
            "MOYEN": "🟡",
            "FAIBLE": "🟢"
        }

        col1.metric("Score de Risque Global", f"{results['risk_score']} / 100")
        col2.metric("Niveau de Menace", f"{color_map.get(results['threat_level'], '')} {results['threat_level']}")
        col3.metric("Alertes Détectées", len(results['deauth_alerts']) + len(results['evil_twin_alerts']))

        st.divider()

        # Section Module 1 - Deauth
        st.subheader("🚨 Module 1 — Détection d'Attaques Deauth Flood")
        if not results['deauth_alerts'].empty:
            st.error(f"**{len(results['deauth_alerts'])} alerte(s) de désauthentification détectée(s)**")
            st.dataframe(results['deauth_alerts'], use_container_width=True)
        else:
            st.success("Aucune anomalie ou attaque Deauth détectée.")

        # Section Module 2 - Evil Twin
        st.subheader("👯 Module 2 — Détection d'Evil Twin & Rogue AP")
        if not results['evil_twin_alerts'].empty:
            st.error(f"**{len(results['evil_twin_alerts'])} point(s) d'accès suspect(s) détecté(s)**")
            st.dataframe(results['evil_twin_alerts'], use_container_width=True)
        else:
            st.success("Aucun doublon de SSID / Evil Twin détecté.")

        # Section Export du rapport
        st.divider()
        st.subheader("📄 Export du Rapport D'Analyse")
        
        report_data = {
            "Fichier analysé": [selected_file],
            "Score de Risque": [f"{results['risk_score']}/100"],
            "Niveau de Menace": [results['threat_level']],
            "Alertes Deauth": [len(results['deauth_alerts'])],
            "Alertes Evil Twin": [len(results['evil_twin_alerts'])],
            "Résumé": ["; ".join(results['threat_summary'])]
        }
        report_df = pd.DataFrame(report_data)
        
        csv_report = report_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="💾 Télécharger le Rapport CSV",
            data=csv_report,
            file_name=f"report_{selected_file}.csv",
            mime="text/csv"
        )