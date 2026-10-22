# src/utils/pdf_generator.py
import os
from fpdf import FPDF

class AuditReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(26, 36, 43)
        self.cell(0, 10, "Wi-Fi Threat Detection & Analysis Report", ln=True, align="C")
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "Rapport d'Audit Technique de Securite 802.11", ln=True, align="C")
        self.line(10, 28, 200, 28)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()} - Document genere automatiquement", align="C")

def generate_pdf_report(results, output_filename="audit_report.pdf"):
    pdf = AuditReportPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pcap_name = os.path.basename(results.get("pcap_path", "Inconnu"))
    risk_score = results.get("risk_score", 0)
    threat_level = results.get("threat_level", "FAIBLE")
    summaries = results.get("threat_summary", [])

    # Section 1 : Synthese de l'Analyse
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(26, 36, 43)
    pdf.cell(0, 8, "1. Synthese de l'Analyse Réseau", ln=True)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 6, "Fichier PCAP analyse :", ln=False)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, pcap_name, ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 6, "Score de Risque Global :", ln=False)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"{risk_score} / 100", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(50, 6, "Niveau de Menace :", ln=False)
    pdf.set_font("Helvetica", "B", 10)
    
    # Couleurs du niveau de menace
    if threat_level == "CRITIQUE":
        pdf.set_text_color(200, 30, 30)
    elif threat_level in ["ELEVE", "ÉLEVÉ"]:
        pdf.set_text_color(220, 100, 0)
    else:
        pdf.set_text_color(0, 130, 50)
        
    pdf.cell(0, 6, threat_level, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Section 2 : Preuves & Elements Detectes
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "2. Preuves et Synthese des Alertes", ln=True)
    pdf.set_font("Helvetica", "", 10)

    if summaries:
        for item in summaries:
            pdf.cell(10, 6, "-", ln=False)
            pdf.cell(0, 6, item, ln=True)
    else:
        pdf.cell(0, 6, "Aucune menace ou anomalie majeure detectee.", ln=True)

    pdf.ln(6)

    # Section 3 : Details Module Deauth
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "3. Detail Module 1 - Attaques Deauth / Disassociation", ln=True)
    pdf.set_font("Helvetica", "", 9)

    deauth_df = results.get("deauth_alerts")
    if deauth_df is not None and not deauth_df.empty:
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(45, 6, "MAC Source", border=1, fill=True)
        pdf.cell(45, 6, "BSSID", border=1, fill=True)
        pdf.cell(30, 6, "Total Deauth", border=1, fill=True)
        pdf.cell(35, 6, "Max Burst (5s)", border=1, fill=True)
        pdf.cell(35, 6, "Severite", border=1, ln=True, fill=True)

        for _, row in deauth_df.iterrows():
            pdf.cell(45, 6, str(row.get('source_mac', '')), border=1)
            pdf.cell(45, 6, str(row.get('bssid', '')), border=1)
            pdf.cell(30, 6, str(row.get('deauth_count', '')), border=1)
            pdf.cell(35, 6, str(row.get('max_burst_5s', '')), border=1)
            pdf.cell(35, 6, str(row.get('severity', '')), border=1, ln=True)
    else:
        pdf.cell(0, 6, "Aucune anomalie Deauth/Disassociation relevee.", ln=True)

    pdf.ln(6)

    # Section 4 : Details Module Evil Twin
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "4. Detail Module 2 - Evil Twin & Constructeurs MAC (OUI)", ln=True)
    pdf.set_font("Helvetica", "", 9)

    evil_df = results.get("evil_twin_alerts")
    if evil_df is not None and not evil_df.empty:
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(35, 6, "SSID", border=1, fill=True)
        pdf.cell(20, 6, "Count", border=1, fill=True)
        pdf.cell(75, 6, "Constructeurs (OUI Vendors)", border=1, fill=True)
        pdf.cell(60, 6, "Niveau de Suspicion", border=1, ln=True, fill=True)

        for _, row in evil_df.iterrows():
            pdf.cell(35, 6, str(row.get('ssid', ''))[:18], border=1)
            pdf.cell(20, 6, str(row.get('bssid_count', '')), border=1)
            pdf.cell(75, 6, str(row.get('vendors', ''))[:40], border=1)
            pdf.cell(60, 6, str(row.get('threat_level', ''))[:30], border=1, ln=True)
    else:
        pdf.cell(0, 6, "Aucun point d'acces duplique ou suspect releve.", ln=True)

    pdf.output(output_filename)
    return output_filename