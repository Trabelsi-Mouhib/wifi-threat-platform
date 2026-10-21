# src/detectors/deauth_detector.py
from scapy.all import rdpcap, Dot11Deauth
import pandas as pd

def detect_deauth_attacks(pcap_path, threshold=10):
    """
    Analyse un fichier PCAP pour détecter les rafales de trames Deauth.
    
    :param pcap_path: Chemin du fichier .pcap à analyser
    :param threshold: Nombre minimal de trames Deauth pour déclarer une alerte
    :return: DataFrame Pandas contenant le résumé des alertes
    """
    print(f"[*] Analyse de : {pcap_path}")
    packets = rdpcap(pcap_path)
    
    deauth_events = []

    for pkt in packets:
        # Vérifie si le paquet contient une couche de désauthentification 802.11
        if pkt.haslayer(Dot11Deauth):
            dot11 = pkt.getlayer(Dot11Deauth)
            
            # Extraction des adresses MAC
            # addr1 = Cible (Destination)
            # addr2 = Source (AP ou Attaquant usurpateur)
            # addr3 = BSSID (Identifiant du réseau Wi-Fi)
            target_mac = pkt.addr1 if hasattr(pkt, 'addr1') else "Unknown"
            source_mac = pkt.addr2 if hasattr(pkt, 'addr2') else "Unknown"
            bssid = pkt.addr3 if hasattr(pkt, 'addr3') else "Unknown"
            reason_code = dot11.reason

            deauth_events.append({
                "source_mac": source_mac,
                "target_mac": target_mac,
                "bssid": bssid,
                "reason_code": reason_code,
                "timestamp": float(pkt.time)
            })

    if not deauth_events:
        print("[+] Aucune trame de désauthentification trouvée.")
        return pd.DataFrame()

    df = pd.DataFrame(deauth_events)
    
    # Agrégation par paire Source -> Cible
    summary = df.groupby(["source_mac", "target_mac", "bssid"]).size().reset_index(name="deauth_count")
    
    # Filtrage selon le seuil d'alerte
    alerts = summary[summary["deauth_count"] >= threshold].copy()
    alerts["severity"] = alerts["deauth_count"].apply(
        lambda count: "CRITICAL" if count >= 50 else ("HIGH" if count >= 20 else "WARNING")
    )

    return alerts

if __name__ == "__main__":
    import sys
    
    # Fichier à tester (par défaut le fichier d'attaque)
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "data/raw/attack_sample.pcap"
    
    results = detect_deauth_attacks(target_pcap)
    
    if not results.empty:
        print("\n[!] ALERTE : Attaque(s) Deauth détectée(s) !")
        print(results.to_string(index=False))
    else:
        print("\n[+] Trafic sain ou sous le seuil d'alerte.")