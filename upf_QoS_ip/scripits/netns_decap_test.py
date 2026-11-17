"""
Test della DECAPSULAZIONE uplink (punto 2, fase 2) e Rate Limiting GCRA.

Va eseguito DENTRO ns-gnb:
    sudo ip netns exec ns-gnb python3 netns_decap_test.py

A differenza di test_gtpu_ext.py (punto 3), qui il payload del GTP non è
testo ma un vero pacchetto IPv4/UDP: è quello che il programma XDP deve far
uscire intatto su veth-n6 dopo aver tolto Eth/IP/UDP/GTP esterni[cite: 10].

Verifica, in un altro terminale:
    sudo ip netns exec ns-dn tcpdump -i veth-dn -n -X udp port 5000
(il pacchetto in uscita è "nudo", senza GTP: un tcpdump semplice basta; per
il downlink/encap usa invece gtp_watch.py, che decodifica il GTP-U)[cite: 10].
"""

import struct
import time
import socket

from scapy.all import Ether, IP, UDP, Raw, sendp

from netns_topology import (
    IFACE_GNB, MAC_GNB, MAC_N3, IP_GNB, IP_N3, IP_DN,
    UE_IP, TEID_UL, TEID_UL_DROP, GTP_PORT,
)

# Riduciamo la pausa a 0 per simulare un "burst" di traffico e 
# saturare rapidamente il secchio del GCRA/TC per vedere i DROP QoS.
PAUSA = 0.00 
DN_PORT = 5000

EXT_PDU_SESSION = 0x85
EXT_UDP_PORT = 0x40


def gtp_u(flags, body=b"", teid=TEID_UL, msg_type=255):
    """Header obbligatorio (8 byte) + body. length = byte che seguono i primi 8."""
    return struct.pack("!BBHI", flags, msg_type, len(body), teid) + body


def opt(next_type=0, seq=1, npdu=0):
    return struct.pack("!HBB", seq, npdu, next_type)


def ext_pdu_session(qfi, next_type=0, pdu_type=0):
    return struct.pack("!BBBB", 1, pdu_type << 4, qfi & 0x3F, next_type)


def ext_riempitivo(next_type):
    return struct.pack("!BHB", 1, GTP_PORT, next_type)


def inner_packet(sport):
    """Pacchetto interno reale: UE (10.60.0.1) -> host nella DN (10.0.6.2).
    Deve uscire intatto su veth-dn dopo la decap."""
    return bytes(IP(src=UE_IP, dst=IP_DN) / UDP(sport=sport, dport=DN_PORT) / Raw("ping-dn"))


# Riduciamo l'elenco ai casi utili per testare il traffico pesante
CASI = [
    ("uplink base, nessun extension header (TEID valido, FORWARD)",
     gtp_u(0x30, inner_packet(4001)),
     "il pacchetto interno esce su veth-dn, intatto"),

    ("uplink con QFI nel PDU Session Container",
     gtp_u(0x34, opt(EXT_PDU_SESSION) + ext_pdu_session(5) + inner_packet(4002)),
     "il pacchetto interno esce su veth-dn, intatto (il QFI non deve alterare il decap)"),

    ("uplink con catena di due extension header",
     gtp_u(0x34, opt(EXT_UDP_PORT) + ext_riempitivo(EXT_PDU_SESSION)
           + ext_pdu_session(9) + inner_packet(4003)),
     "il pacchetto interno esce su veth-dn, intatto"),
]


def main():
    print("==================================================")
    print(" FASE 1: Raffica aggressiva per testare GCRA & TC ")
    print("==================================================")
    
    # Invia tutti i pacchetti in modo ravvicinato per testare il Policing
    for nome, gtp_payload, atteso in CASI:
        # Moltiplichiamo ogni caso per 4 per generare un volume sufficiente 
        # a far scattare il rate limiter
        for _ in range(5000): 
            pkt = (
                Ether(src=MAC_GNB, dst=MAC_N3)
                / IP(src=IP_GNB, dst=IP_N3)
                / UDP(sport=50000, dport=GTP_PORT)
                / Raw(gtp_payload)
            )
            sendp(pkt, iface=IFACE_GNB, verbose=False)
            time.sleep(PAUSA) # Micro-pausa per non intasare Scapy, ma sufficiente per il TC
            
        print(f"[{nome}]\n    atteso: {atteso}")
        
    print("\n==================================================")
    print(" FASE 2: Pausa per il reset del TAT (Refill)      ")
    print("==================================================")
    time.sleep(3) # Tempo sufficiente per far tornare il TAT indietro rispetto a 'now'
    
    print("\n==================================================")
    print(" FASE 3: Invio pacchetto post-reset               ")
    print("==================================================")
    # Mandiamo l'ultimo pacchetto "base", dovrebbe passare (Verde)
    pkt_finale = (
        Ether(src=MAC_GNB, dst=MAC_N3)
        / IP(src=IP_GNB, dst=IP_N3)
        / UDP(sport=50000, dport=GTP_PORT)
        / Raw(CASI[0][1])
    )
    sendp(pkt_finale, iface=IFACE_GNB, verbose=False)
    print("Pacchetto post-reset inviato.")

if __name__ == "__main__":
    main()