# src/analysis_engine.py
import pandas as pd
from src.detectors.deauth_detector import detect_deauth_attacks
from src.detectors.evil_twin_detector import detect_evil_twins

def analyze_pcap(pcap_path):
    """
    Analyse globale d'un fichier PCAP avec agrégation des alertes,
    vérification des constructeurs MAC et calcul du score de risque.
    """
    deauth_alerts = detect_deauth_attacks(pcap_path, burst_threshold=3, window_seconds=5)
    evil_twin_alerts = detect_evil_twins(pcap_path)

    risk_score = 0
    threat_summary = []

    # 1. Traitement des alertes Deauth
    if not deauth_alerts.empty:
        max_burst = deauth_alerts["max_burst_5s"].max()
        if max_burst >= 20:
            risk_score += 50
        elif max_burst >= 10:
            risk_score += 35
        else:
            risk_score += 20
        threat_summary.append(f"Rafale Deauth/Disassoc (max {max_burst} trames/5s)")

    # 2. Traitement des alertes Evil Twin avec vérification OUI Vendor
    if not evil_twin_alerts.empty:
        max_suspicion = evil_twin_alerts["suspicion_score"].max()
        risk_score += max_suspicion / 2  # Poids ajusté selon le niveau de certitude OUI

        vendors_involved = evil_twin_alerts["vendors"].tolist()
        threat_summary.append(f"Evil Twin / Rogue AP suspecté (Constructeurs: {', '.join(vendors_involved)})")

    # Corrélation critique (Attaque Deauth + Evil Twin simultanés)
    if not deauth_alerts.empty and not evil_twin_alerts.empty:
        risk_score += 15
        threat_summary.append("COMBINAISON CRITIQUE : Deauth Flood + Evil Twin")

    risk_score = min(int(risk_score), 100)

    if risk_score >= 75:
        threat_level = "CRITIQUE"
    elif risk_score >= 45:
        threat_level = "ÉLEVÉ"
    elif risk_score >= 20:
        threat_level = "MOYEN"
    else:
        threat_level = "FAIBLE"

    return {
        "pcap_path": pcap_path,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "threat_summary": threat_summary,
        "deauth_alerts": deauth_alerts,
        "evil_twin_alerts": evil_twin_alerts
    }

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "data/raw/attack_sample.pcap"
    results = analyze_pcap(target)
    print(f"\n[+] Score de risque global : {results['risk_score']}/100 ({results['threat_level']})")
    print(f"[+] Résumé : {', '.join(results['threat_summary'])}")