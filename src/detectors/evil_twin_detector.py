# src/detectors/evil_twin_detector.py
from scapy.all import rdpcap, Dot11Beacon, Dot11Elt
import pandas as pd
from mac_vendor_lookup import MacLookup

# Initialisation du résolveur MAC OUI
lookup = MacLookup()

def get_vendor(mac_address):
    """Résout le constructeur à partir du préfixe MAC (OUI IEEE)."""
    try:
        return lookup.lookup(mac_address)
    except Exception:
        return "Inconnu / Non enregistré"

def detect_evil_twins(pcap_path):
    """
    Détection multi-critères d'Evil Twin / Rogue AP basée sur :
    - La duplication de SSID sur différents BSSIDs
    - La divergence de constructeur (OUI Vendor)
    """
    print(f"[*] Analyse Evil Twin de : {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Erreur de lecture du fichier : {e}")
        return pd.DataFrame()

    aps = {}

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr3 if hasattr(pkt, 'addr3') and pkt.addr3 else "Unknown"
            
            # Extraire le SSID depuis la trame Beacon
            elt = pkt.getlayer(Dot11Elt)
            ssid = None
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0:  # ID 0 = SSID
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    except Exception:
                        ssid = str(elt.info)
                    break
                elt = elt.payload

            if bssid and ssid and bssid not in aps:
                vendor = get_vendor(bssid)
                aps[bssid] = {
                    "bssid": bssid,
                    "ssid": ssid,
                    "vendor": vendor
                }

    if not aps:
        print("[+] Aucune trame Beacon trouvée.")
        return pd.DataFrame()

    df_aps = pd.DataFrame(list(aps.values()))
    
    # Filtrer les SSID masqués ou vides
    df_aps = df_aps[df_aps['ssid'].str.strip() != ""]

    alerts = []

    # Regroupement par SSID
    grouped = df_aps.groupby("ssid")

    for ssid, group in grouped:
        # S'il y a au moins 2 BSSID différents pour un même SSID
        if len(group) > 1:
            vendors = group["vendor"].unique()
            bssids = group["bssid"].tolist()

            # Indice de suspicion : Si les constructeurs sont différents, c'est très probablement un Evil Twin
            if len(vendors) > 1:
                threat_level = "CRITIQUE (Constructeurs MAC divergents)"
                suspicion_score = 90
            else:
                threat_level = "SUSPECT (Possible Roaming Légitime ou Evil Twin Clané)"
                suspicion_score = 45

            alerts.append({
                "ssid": ssid,
                "bssid_count": len(group),
                "bssids": ", ".join(bssids),
                "vendors": ", ".join(vendors),
                "threat_level": threat_level,
                "suspicion_score": suspicion_score
            })

    if not alerts:
        print("[+] Aucun doublon de SSID suspect détecté.")
        return pd.DataFrame()

    return pd.DataFrame(alerts)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "data/raw/attack_sample.pcap"
    res = detect_evil_twins(target)
    if not res.empty:
        print("\n[!] ALERTE : Evil Twin détecté !")
        print(res.to_string(index=False))
    else:
        print("\n[+] Aucun Evil Twin détecté.")