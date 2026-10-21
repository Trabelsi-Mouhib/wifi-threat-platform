# evaluate.py
import json
import os
import sys
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from src.detectors.deauth_detector import detect_deauth_attacks
from src.detectors.evil_twin_detector import detect_evil_twins

GROUND_TRUTH_PATH = "data/ground_truth.json"
RAW_DIR = "data/raw"

def load_ground_truth():
    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"[!] Erreur : Fichier {GROUND_TRUTH_PATH} introuvable.")
        sys.exit(1)
    with open(GROUND_TRUTH_PATH, "r") as f:
        return json.load(f)

def run_evaluation():
    ground_truth = load_ground_truth()

    y_true_deauth, y_pred_deauth = [], []
    y_true_evil, y_pred_evil = [], []

    print("=" * 60)
    print(" 🧪 ÉVALUATION DES PERFORMANCES DU DÉTECTEUR")
    print("=" * 60)

    for pcap_name, labels in ground_truth.items():
        pcap_path = os.path.join(RAW_DIR, pcap_name)

        if not os.path.exists(pcap_path):
            print(f"[⚠️] Fichier {pcap_name} introuvable dans {RAW_DIR}, ignoré.")
            continue

        print(f"[*] Analyse de : {pcap_name} ...")

        # Module 1 : Nouveau détecteur Deauth (avec burst_threshold)
        deauth_res = detect_deauth_attacks(pcap_path, burst_threshold=3, window_seconds=5)
        y_true_deauth.append(1 if labels["has_deauth_attack"] else 0)
        y_pred_deauth.append(1 if not deauth_res.empty else 0)

        # Module 2 : Détecteur Evil Twin
        evil_res = detect_evil_twins(pcap_path)
        y_true_evil.append(1 if labels["has_evil_twin"] else 0)
        y_pred_evil.append(1 if not evil_res.empty else 0)

    print("\n" + "=" * 60)
    print(" 📊 RÉSULTATS MÉTROLOGIQUES")
    print("=" * 60)

    modules = [
        ("Module 1 : Deauth Flood (Fenêtres Glissantes)", y_true_deauth, y_pred_deauth),
        ("Module 2 : Evil Twin / Rogue AP", y_true_evil, y_pred_evil)
    ]

    for name, y_true, y_pred in modules:
        print(f"\n--- {name} ---")
        if not y_true:
            print("Aucune donnée évaluée.")
            continue

        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

        vn, fp, fn, vp = cm.ravel()

        print(f"Précision  : {prec:.2%}")
        print(f"Rappel     : {rec:.2%}")
        print(f"Score F1   : {f1:.2%}")
        print(f"Matrice de Confusion :")
        print(f"  [Vrais Négatifs={vn}  Faux Positifs={fp}]")
        print(f"  [Faux Négatifs={fn}  Vrais Positifs={vp}]")

if __name__ == "__main__":
    run_evaluation()