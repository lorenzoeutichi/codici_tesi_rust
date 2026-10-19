from scapy.all import Ether, IP, UDP, sendp
from scapy.contrib.gtp import GTP_U_Header

N_PKT = 5  # pacchetti per ogni TEID

# TEID -> esito atteso con le regole caricate in main.rs
TEIDS = {
    9999: "forward    (PDR -> FAR 1, FORWARD)",
    8888: "drop (FAR) (PDR -> FAR 2, DROP)",
    6666: "nessun PDR (TEID non inserito)",
}

payload = b"Test_Payload_5G"

for teid, atteso in TEIDS.items():
    pkt = (
        Ether()
        / IP(dst="127.0.0.1")
        / UDP(sport=50000, dport=2152)
        / GTP_U_Header(teid=teid, gtp_type=255)  # 255 = G-PDU
        / payload
    )
    for _ in range(N_PKT):
        sendp(pkt, iface="lo", verbose=False)
    print(f"Inviati {N_PKT} pacchetti con TEID {teid} -> atteso: {atteso}")