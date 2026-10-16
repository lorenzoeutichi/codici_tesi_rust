from scapy.all import Ether, IP, UDP, sendp
from scapy.contrib.gtp import GTP_U_Header

# Crea un pacchetto IP verso localhost
ip_layer = IP(dst="127.0.0.1")

# Crea il livello UDP mirato alla porta standard GTP-U
udp_layer = UDP(sport=50000, dport=2152)

# Crea l'header GTPv1 (GTP_U_Header in Scapy gestisce in automatico i flag 0x30 per v1)
# gtp_type 255 equivale a G-PDU (traffico utente)
gtp_layer = GTP_U_Header(teid=9999, gtp_type=255)

# Payload fittizio
payload = b"Test_Payload_5G"

# Assembla il pacchetto in un Frame Ethernet
pkt = Ether() / ip_layer / udp_layer / gtp_layer / payload

for _ in range(5):
    sendp(pkt, iface="lo")
    print("Invio pacchetto GTP-U con TEID 9999 e Msg Type 255...")

