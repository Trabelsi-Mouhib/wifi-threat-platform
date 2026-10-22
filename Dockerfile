FROM python:3.11-slim

# Installation des dépendances système nécessaires à Scapy et PCAP
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Création du dossier cache puis téléchargement de la base MAC OUI
RUN mkdir -p /root/.cache && python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"

# Copie du code source et des données
COPY . .

# Exposition du port Streamlit
EXPOSE 8501

# Lancement de l'interface Streamlit
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501"]