# src/detectors/deauth_detector.py
from scapy.all import rdpcap, Dot11Deauth, Dot11Disas
import pandas as pd

def detect_deauth_attacks(pcap_path, burst_threshold=3, window_seconds=5):
    """
    Analyse comportementale des attaques Deauth / Disassociation
    utilisant des fenêtres glissantes temporelles avec Pandas.
    """
    print(f"[*] Analyse de : {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Erreur de lecture du fichier : {e}")
        return pd.DataFrame()
    
    deauth_events = []

    for pkt in packets:
        # Ingestion des trames Deauth (subtype 12) et Disassoc (subtype 10)
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            layer_type = "Deauth" if pkt.haslayer(Dot11Deauth) else "Disassoc"
            
            target_mac = pkt.addr1 if hasattr(pkt, 'addr1') and pkt.addr1 else "ff:ff:ff:ff:ff:ff"
            source_mac = pkt.addr2 if hasattr(pkt, 'addr2') and pkt.addr2 else "Unknown"
            bssid = pkt.addr3 if hasattr(pkt, 'addr3') and pkt.addr3 else "Unknown"
            
            reason_code = None
            if pkt.haslayer(Dot11Deauth):
                reason_code = pkt.getlayer(Dot11Deauth).reason
            elif pkt.haslayer(Dot11Disas):
                reason_code = pkt.getlayer(Dot11Disas).reason

            deauth_events.append({
                "source_mac": source_mac,
                "target_mac": target_mac,
                "bssid": bssid,
                "type": layer_type,
                "reason_code": reason_code,
                "timestamp": pd.to_datetime(float(pkt.time), unit='s')
            })

    if not deauth_events:
        print("[+] Aucune trame de désauthentification/désassociation trouvée.")
        return pd.DataFrame()

    df = pd.DataFrame(deauth_events)
    df = df.sort_values("timestamp")

    alerts = []
    
    # Groupement par couple (Source, BSSID)
    grouped = df.groupby(["source_mac", "bssid"])

    for (source_mac, bssid), group in grouped:
        group_indexed = group.set_index("timestamp")
        
        # Calcul du nombre de trames dans chaque fenêtre glissante (ex: 5s)
        rolling_count = group_indexed["type"].rolling(f"{window_seconds}s").count()
        max_burst = int(rolling_count.max())
        total_count = len(group)

        # Condition d'alerte : Rafale dense dans la fenêtre OU total élevé
        if max_burst >= burst_threshold or total_count >= 5:
            if max_burst >= 20:
                severity = "CRITICAL"
            elif max_burst >= 10:
                severity = "HIGH"
            else:
                severity = "WARNING"

            alerts.append({
                "source_mac": source_mac,
                "bssid": bssid,
                "deauth_count": total_count,
                "max_burst_5s": max_burst,
                "severity": severity
            })

    if not alerts:
        print("[+] Trafic sous le seuil d'alerte.")
        return pd.DataFrame()

    return pd.DataFrame(alerts)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "data/raw/attack_sample.pcap"
    res = detect_deauth_attacks(target)
    if not res.empty:
        print("\n[!] ALERTE : Attaque(s) Deauth détectée(s) !")
        print(res.to_string(index=False))
    else:
        print("\n[+] Aucun événement suspect.")