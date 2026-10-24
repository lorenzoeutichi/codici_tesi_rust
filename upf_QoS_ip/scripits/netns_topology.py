"""Costanti della topologia creata da setup_netns.sh.

Importato dagli altri script di test, così IP/MAC/TEID restano coerenti in un
unico posto. Se cambi setup_netns.sh, aggiorna anche questo file.
"""

# --- interfacce / indirizzi (devono combaciare con setup_netns.sh) ---
IFACE_GNB = "veth-gnb"   # dentro ns-gnb
IFACE_N3 = "veth-n3"     # dentro la root ns (lato gNB) — qui si aggancia l'XDP uplink
IFACE_DN = "veth-dn"     # dentro ns-dn
IFACE_N6 = "veth-n6"     # dentro la root ns (lato DN) — qui si aggancia l'XDP downlink

MAC_GNB = "02:00:00:00:03:02"
MAC_N3 = "02:00:00:00:03:01"
MAC_DN = "02:00:00:00:06:02"
MAC_N6 = "02:00:00:00:06:01"

IP_GNB = "10.0.3.2"
IP_N3 = "10.0.3.1"
IP_DN = "10.0.6.2"
IP_N6 = "10.0.6.1"

GTP_PORT = 2152

# --- piano utente / regole caricate nel loader (da tenere allineate a main.rs) ---
UE_IP = "10.60.0.1"       # IP dell'UE simulato, usato come dst nel traffico downlink
TEID_UL = 9999            # TEID lato N3 per il traffico uplink (PDR -> FAR FORWARD)
TEID_UL_DROP = 8888       # TEID con FAR DROP, per i test negativi
TEID_DL = 7001            # TEID che l'UPF deve scrivere nell'header GTP in downlink