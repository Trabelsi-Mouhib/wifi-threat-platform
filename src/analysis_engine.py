# src/analysis_engine.py
import pandas as pd
from src.detectors.deauth_detector import detect_deauth_attacks
from src.detectors.evil_twin_detector import detect_evil_twins

def analyze_pcap(pcap_path):
    """
    Analyse un fichier PCAP à l'aide des modules Deauth et Evil Twin,
    puis calcule un score de risque global.
    """
    deauth_alerts = detect_deauth_attacks(pcap_path, threshold=10)
    evil_twin_alerts = detect_evil_twins(pcap_path)

    # Calcul du score de risque global (sur 100)
    risk_score = 0
    threat_summary = []

    has_deauth = not deauth_alerts.empty
    has_evil_twin = not evil_twin_alerts.empty

    if has_deauth:
        max_deauths = deauth_alerts["deauth_count"].max()
        if max_deauths >= 50:
            risk_score += 45
        else:
            risk_score += 25
        threat_summary.append("Attaque par désauthentification détectée")

    if has_evil_twin:
        risk_score += 45
        threat_summary.append("Point d'accès malveillant (Evil Twin) détecté")

    # Corrélation des menaces (Deauth + Evil Twin en même temps = attaque ciblée active)
    if has_deauth and has_evil_twin:
        risk_score += 10  # Bonus de risque pour corrélation
        threat_summary.append("COMBINAISON CRITIQUE : Deauth + Evil Twin")

    # Plafonner le score à 100
    risk_score = min(risk_score, 100)

    # Qualification du niveau de menace
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