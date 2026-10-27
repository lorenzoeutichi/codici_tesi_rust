"""
Test della INCAPSULAZIONE downlink (punto 2, fasi 3 e 4).

Va eseguito DENTRO ns-dn:
    sudo ip netns exec ns-dn python3 netns_encap_test.py

Invia un pacchetto UDP verso l'IP dell'UE (10.60.0.1). Grazie alla route
"10.60.0.0/16 via veth-n6" impostata da setup_netns.sh, il kernel lo instrada
verso l'UPF, che deve incapsularlo in GTP-U e inviarlo su veth-n3 al gNB
(10.0.3.2) con TEID 7001.

Verifica, in un altro terminale:
    sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152
"""
import time

from scapy.all import IP, UDP, Raw, send

from netns_topology import UE_IP

UE_PORT = 3000
PAUSA = 1.0

CASI = [
    ("downlink verso l'UE, innesca l'encap",
     IP(dst=UE_IP) / UDP(sport=6000, dport=UE_PORT) / Raw(b"hello-ue")),
]


def main():
    for nome, pkt in CASI:
        send(pkt, verbose=False)
        print(f"[{nome}] inviato -> controlla veth-gnb con gtp_watch.py")
        time.sleep(PAUSA)


if __name__ == "__main__":
    main()