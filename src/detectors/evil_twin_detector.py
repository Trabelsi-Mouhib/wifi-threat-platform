# src/detectors/evil_twin_detector.py
from scapy.all import rdpcap, Dot11Beacon, Dot11Elt
import pandas as pd

def extract_beacon_info(pcap_path):
    """Parcourt le PCAP et extrait les informations des trames Beacon."""
    packets = rdpcap(pcap_path)
    ap_list = []

    for pkt in packets:
        # Vérifie si le paquet est une trame de gestion Beacon
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr3 if hasattr(pkt, 'addr3') else "Unknown"
            ssid = "Hidden SSID"
            channel = None

            # Parcours des éléments d'information (IE) de la trame 802.11
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                # ID 0 = SSID
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="ignore")
                    except Exception:
                        ssid = str(elt.info)
                # ID 3 = DS Parameter Set (Canal radio)
                elif elt.ID == 3 and len(elt.info) == 1:
                    channel = ord(elt.info)
                
                elt = elt.payload.getlayer(Dot11Elt)

            if ssid and ssid != "Hidden SSID":
                ap_list.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel,
                    "timestamp": float(pkt.time)
                })

    return pd.DataFrame(ap_list)

def detect_evil_twins(pcap_path):
    """
    Analyse les réseaux Wi-Fi pour identifier les doublons de SSID
    associés à des BSSID différents.
    """
    print(f"[*] Analyse Evil Twin de : {pcap_path}")
    df = extract_beacon_info(pcap_path)

    if df.empty:
        print("[+] Aucune trame Beacon trouvée.")
        return pd.DataFrame()

    # Dédoublonnage des paires (SSID, BSSID)
    unique_aps = df.groupby(["ssid", "bssid"]).agg(
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        beacon_count=("timestamp", "count")
    ).reset_index()

    # Recherche des SSID qui ont plus d'un BSSID associe
    ssid_counts = unique_aps.groupby("ssid")["bssid"].nunique().reset_index(name="bssid_count")
    suspicious_ssids = ssid_counts[ssid_counts["bssid_count"] > 1]["ssid"]

    if suspicious_ssids.empty:
        print("[+] Aucun doublon de SSID détecté.")
        return pd.DataFrame()

    # Extraction des alertes
    alerts = unique_aps[unique_aps["ssid"].isin(suspicious_ssids)].copy()
    alerts["severity"] = "HIGH"

    return alerts

if __name__ == "__main__":
    import sys
    
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "data/raw/attack_sample.pcap"
    alerts = detect_evil_twins(target_pcap)

    if not alerts.empty:
        print("\n[!] ALERTE : Point(s) d'accès Evil Twin / Rogue AP détecté(s) !")
        print(alerts.to_string(index=False))
    else:
        print("\n[+] Aucun point d'accès suspect détecté.")