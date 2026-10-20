"""
Test del parsing GTP-U: campi opzionali, extension header, QFI.

Gli header GTP-U sono costruiti a mano con struct.pack, così i byte inviati
sono esattamente quelli voluti (Scapy a volte imposta flag e length da solo).

Uso (con il loader avviato su lo, RUST_LOG=info):
    sudo python3 test_gtpu_ext.py
Poi si confrontano i log del loader con la colonna "atteso" stampata qui.
"""
import struct
import time

from scapy.all import Ether, IP, UDP, Raw, sendp

IFACE = "lo"
TEID = 9999          # ha un PDR -> FAR 1 (FORWARD)
PAUSA = 1.0          # secondi tra un caso e l'altro, per far combaciare i log
PAYLOAD = b"Test_Payload_5G"
GTP_OFF = 14 + 20 + 8  # Ethernet + IPv4 (senza opzioni) + UDP: qui inizia il GTP

EXT_UDP_PORT = 0x40       # extension header usato come riempitivo
EXT_PDU_SESSION = 0x85    # PDU Session Container


def gtp_u(flags, body=b"", teid=TEID, msg_type=255):
    """Header obbligatorio (8 byte) + body.
    length = byte che seguono i primi 8 (opzionali + extension header + payload)."""
    return struct.pack("!BBHI", flags, msg_type, len(body), teid) + body


def opt(next_type=0, seq=1, npdu=0):
    """4 byte opzionali: sequence number (2), N-PDU (1), next extension type (1)."""
    return struct.pack("!HBB", seq, npdu, next_type)


def ext_pdu_session(qfi, next_type=0, pdu_type=0):
    """PDU Session Container da 4 byte: len=1, tipo PDU, QFI, next type."""
    return struct.pack("!BBBB", 1, pdu_type << 4, qfi & 0x3F, next_type)


def ext_pdu_session_len2(qfi, next_type=0):
    """PDU Session Container da 8 byte (len=2): 4 byte di contenuto in più."""
    return struct.pack("!BBB", 2, 0, qfi & 0x3F) + b"\x00" * 4 + bytes([next_type])


def ext_riempitivo(next_type):
    """Extension header generico da 4 byte (len=1, 2 byte di contenuto)."""
    return struct.pack("!BHB", 1, 2152, next_type)


# (nome, header GTP completo, atteso)
CASI = [
    ("base, nessun campo opzionale (0x30)",
     gtp_u(0x30, PAYLOAD),
     "off=50 qfi=255"),

    ("solo S (0x32)",
     gtp_u(0x32, opt(0) + PAYLOAD),
     "off=54 qfi=255"),

    ("S con next_type=0x85 ma E spento (0x32): il byte va ignorato",
     gtp_u(0x32, opt(EXT_PDU_SESSION) + PAYLOAD),
     "off=54 qfi=255"),

    ("E senza extension header (0x34)",
     gtp_u(0x34, opt(0) + PAYLOAD),
     "off=54 qfi=255"),

    ("E + PDU Session Container, QFI 5 (0x34)",
     gtp_u(0x34, opt(EXT_PDU_SESSION) + ext_pdu_session(5) + PAYLOAD),
     "off=58 qfi=5"),

    ("E + PDU Session Container, QFI 63 (6 bit pieni)",
     gtp_u(0x34, opt(EXT_PDU_SESSION) + ext_pdu_session(63) + PAYLOAD),
     "off=58 qfi=63"),

    ("container da 8 byte (len=2), QFI 5",
     gtp_u(0x34, opt(EXT_PDU_SESSION) + ext_pdu_session_len2(5) + PAYLOAD),
     "off=62 qfi=5"),

    ("catena: header 0x40 poi container, QFI 9",
     gtp_u(0x34, opt(EXT_UDP_PORT) + ext_riempitivo(EXT_PDU_SESSION)
           + ext_pdu_session(9) + PAYLOAD),
     "off=62 qfi=9"),

    ("len=0 (malformato)",
     gtp_u(0x34, opt(EXT_PDU_SESSION) + b"\x00\x00\x09\x00" + PAYLOAD),
     "nessun log 'offset: ...': XDP_PASS prima del log (len=0)"),

    ("catena troppo lunga: 4 header 0x40 (limite del ciclo = 3)",
     gtp_u(0x34, opt(EXT_UDP_PORT) + ext_riempitivo(EXT_UDP_PORT) * 3
           + ext_riempitivo(0) + PAYLOAD),
     "nessun log 'offset: ...': XDP_PASS, la catena supera il limite di 3 header"),

    ("troncato: E acceso ma il pacchetto finisce dopo i primi 8 byte",
     gtp_u(0x34),
     "nessun log 'offset: ...': ptr_at fallisce, XDP_PASS"),
]


def main():
    for nome, gtp, atteso in CASI:
        pkt = Ether() / IP(dst="127.0.0.1") / UDP(sport=50000, dport=2152) / Raw(gtp)
        raw = bytes(pkt)
        assert raw[GTP_OFF] == gtp[0], "offset del GTP inatteso (IP con opzioni?)"
        sendp(pkt, iface=IFACE, verbose=False)
        print(f"[{nome}]")
        print(f"    byte GTP: {raw[GTP_OFF:GTP_OFF + 16].hex(' ')}")
        print(f"    atteso:   {atteso}")
        time.sleep(PAUSA)


if __name__ == "__main__":
    main()