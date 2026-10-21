import os
from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, wrpcap
)

RAW_DIR = "data/raw"
os.makedirs(RAW_DIR, exist_ok=True)

def create_beacon(ssid, bssid, channel=6):
    return (
        RadioTap() /
        Dot11(subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
        Dot11Beacon(cap="ESS+privacy") /
        Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) /
        Dot11Elt(ID="DSset", info=chr(channel))
    )

def create_deauth(target_mac, ap_bssid, reason=7):
    return (
        RadioTap() /
        Dot11(subtype=12, addr1=target_mac, addr2=ap_bssid, addr3=ap_bssid) /
        Dot11Deauth(reason=reason)
    )

def main():
    print("[*] Generating synthetic 802.11 PCAP files...")
    
    # Normal background beacons
    normal_packets = []
    legit_bssid = "00:11:22:33:44:55"
    legit_ssid = "Corporate-WiFi"
    for _ in range(50):
        normal_packets.append(create_beacon(legit_ssid, legit_bssid))
    wrpcap(f"{RAW_DIR}/normal_traffic.pcap", normal_packets)
    print(f"[+] Saved {RAW_DIR}/normal_traffic.pcap")

    # Attack traffic (Evil Twin + Deauth flood)
    attack_packets = []
    for _ in range(20):
        attack_packets.append(create_beacon(legit_ssid, legit_bssid))
        
    rogue_bssid = "aa:bb:cc:dd:ee:ff"
    for _ in range(30):
        attack_packets.append(create_beacon(legit_ssid, rogue_bssid))
        
    client_mac = "12:34:56:78:90:ab"
    for _ in range(60):
        attack_packets.append(create_deauth(client_mac, legit_bssid))
        
    wrpcap(f"{RAW_DIR}/attack_sample.pcap", attack_packets)
    print(f"[+] Saved {RAW_DIR}/attack_sample.pcap")

if __name__ == "__main__":
    main()
