# dashboard/app.py
import sys
import os
import streamlit as st
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analysis_engine import analyze_pcap
from src.utils.pdf_generator import generate_pdf_report

st.set_page_config(
    page_title="Wi-Fi Threat Detection Platform",
    page_icon="📡",
    layout="wide"
)

st.title("📡 Wi-Fi Threat Detection & Analysis Platform")
st.markdown("Plateforme d'analyse et d'évaluation du risque sur captures 802.11 (PCAP)")

st.sidebar.header("📁 Sélection de la Capture Réseau")
raw_dir = "data/raw"

available_files = [f for f in os.listdir(raw_dir) if f.endswith(".pcap") or f.endswith(".pcapng")] if os.path.exists(raw_dir) else []
selected_file = st.sidebar.selectbox("Fichiers de test disponibles :", available_files)

if selected_file:
    pcap_path = os.path.join(raw_dir, selected_file)
    
    if st.sidebar.button("🚀 Lancer l'analyse", use_container_width=True):
        with st.spinner("Analyse approfondie des trames 802.11..."):
            results = analyze_pcap(pcap_path)

        st.subheader("📊 Évaluation Synthétique du Risque")
        col1, col2, col3 = st.columns(3)

        color_map = {
            "CRITIQUE": "🔴",
            "ÉLEVÉ": "🟠",
            "MOYEN": "🟡",
            "FAIBLE": "🟢"
        }

        col1.metric("Score de Risque Global", f"{results['risk_score']} / 100")
        col2.metric("Niveau de Menace", f"{color_map.get(results['threat_level'], '')} {results['threat_level']}")
        col3.metric("Nombre total d'alertes", len(results['deauth_alerts']) + len(results['evil_twin_alerts']))

        st.divider()

        # Section Deauth
        st.subheader("🚨 Module 1 — Attaques Deauth / Disassociation Flood")
        if not results['deauth_alerts'].empty:
            st.error(f"**{len(results['deauth_alerts'])} alerte(s) comportementale(s) détectée(s)**")
            st.dataframe(results['deauth_alerts'], use_container_width=True)
        else:
            st.success("Aucune anomalie ou rafale Deauth/Disassoc détectée.")

        # Section Evil Twin
        st.subheader("👯 Module 2 — Détection Evil Twin & Rogue AP (Analyse OUI)")
        if not results['evil_twin_alerts'].empty:
            st.error(f"**{len(results['evil_twin_alerts'])} point(s) d'accès suspect(s) détecté(s)**")
            st.dataframe(results['evil_twin_alerts'], use_container_width=True)
        else:
            st.success("Aucune duplication de SSID / Evil Twin détectée.")

        # Section Export des Rapports
        st.divider()
        st.subheader("📄 Export des Rapports d'Analyse")
        
        col_export_csv, col_export_pdf = st.columns(2)

        # Export CSV
        report_data = {
            "Fichier": [selected_file],
            "Score Risque": [f"{results['risk_score']}/100"],
            "Niveau Menace": [results['threat_level']],
            "Alertes Deauth": [len(results['deauth_alerts'])],
            "Alertes Evil Twin": [len(results['evil_twin_alerts'])],
            "Détails Preuves": ["; ".join(results['threat_summary'])]
        }
        report_df = pd.DataFrame(report_data)
        csv_report = report_df.to_csv(index=False).encode('utf-8')

        col_export_csv.download_button(
            label="💾 Télécharger le Rapport CSV",
            data=csv_report,
            file_name=f"audit_report_{selected_file}.csv",
            mime="text/csv",
            use_container_width=True
        )

        # Export PDF
        pdf_filename = f"audit_report_{selected_file}.pdf"
        generate_pdf_report(results, pdf_filename)
        
        with open(pdf_filename, "rb") as pdf_file:
            pdf_bytes = pdf_file.read()

        col_export_pdf.download_button(
            label="📕 Télécharger le Rapport PDF",
            data=pdf_bytes,
            file_name=pdf_filename,
            mime="application/pdf",
            use_container_width=True
        )