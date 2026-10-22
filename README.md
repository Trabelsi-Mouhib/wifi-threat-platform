# 📡 Wi-Fi Threat Detection & Analysis Platform

Une plateforme d'analyse comportementale et de détection de menaces sur réseaux 802.11 (PCAP), intégrant un banc de validation métrologique et une interface d'audit interactive.

---

## 🎯 Fonctionnalités Clés

- **Module 1 — Détection Deauth / Disassociation Flood :** Analyse par fenêtres glissantes temporelles (Pandas) pour détecter les rafales (*bursts*) de désauthentification sans faux positifs.
- **Module 2 — Détection Evil Twin & Rogue AP :** Corrélation multi-critères basée sur la duplication de SSID et la résolution des constructeurs d'adresses MAC (**OUI IEEE** via `mac-vendor-lookup`).
- **Banc de Test & Métrologie :** Script d'évaluation automatique (`evaluate.py`) calculant la Précision, le Rappel (*Recall*) et le Score $F_1$ via `scikit-learn` sur vérités terrains (*ground truth*).
- **Tableau de Bord Streamlit :** Visualisation synthétique du risque global, détail des preuves par module et prévisualisation.
- **Rapports d'Audit :** Export instantané des résultats sous formats **CSV** et **PDF** normés (via `fpdf2`).
- **Conteneurisation Docker :** Déploiement via `Docker` et `docker-compose` pour une exécution multi-environnement sans dépendances locales.

---

## 📊 Performances & Métrologie

L'évaluation est mesurée sur un jeu de données hybride (captures réelles de la *Wireshark Sample Captures Library* et simulations d'attaques 802.11) :

| Module | Précision | Rappel (*Recall*) | Score $F_1$ | Statut |
| :--- | :---: | :---: | :---: | :---: |
| **Module 1 : Deauth Flood (Fenêtres Glissantes)** | 100,00 % | 100,00 % | 100,00 % | Validé |
| **Module 2 : Evil Twin / Rogue AP (Analyse OUI)** | 100,00 % | 100,00 % | 100,00 % | Validé |

---

## 🏗️ Architecture du Projet

```text
wifi-threat-platform/
├── dashboard/
│   └── app.py                # Interface Streamlit
├── data/
│   ├── ground_truth.json     # Vérité terrain pour l'évaluation métrologique
│   └── raw/                  # Fichiers PCAP d'analyse
├── src/
│   ├── detectors/
│   │   ├── deauth_detector.py    # Algorithme à fenêtres glissantes
│   │   └── evil_twin_detector.py # Détecteur de doublons & analyse OUI IEEE
│   ├── utils/
│   │   └── pdf_generator.py    # Générateur de rapports d'audit PDF
│   └── analysis_engine.py    # Moteur central d'agrégation et score de risque
├── evaluate.py               # Script d'évaluation métrologique
├── Dockerfile                # Configuration d'image Docker
├── docker-compose.yml        # Orchestration du service
└── requirements.txt          # Dépendances Python

🚀 Installation & Déploiement
Option 1 : Déploiement rapide via Docker Compose (Recommandé)
Bash
# Lancer le service en arrière-plan
docker-compose up --build -d

# Accéder à l'interface web : http://localhost:8501

Pour arrêter le service :

Bash
docker-compose down

Option 2 : Installation locale (Environnement Virtuel Python)
Bash
# 1. Cloner le dépôt et créer l'environnement
git clone [https://github.com/](https://github.com/)<votre-utilisateur>/wifi-threat-platform.git
cd wifi-threat-platform
python3 -m venv venv
source venv/bin/activate

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Initialiser la base de données MAC OUI
python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"

# 4. Lancer le tableau de bord
streamlit run dashboard/app.py
🧪 Exécution des Tests Métrologiques
Pour vérifier les performances des détecteurs sur le jeu de test :

Bash
python evaluate.py