"""
Test della INCAPSULAZIONE downlink e RATE LIMITING (QoS).

Va eseguito DENTRO ns-dn:
    sudo ip netns exec ns-dn python3 netns_qos_dl_test.py

Il test invia una raffica di pacchetti per saturare il limite MBR,
attende la ricarica del Token Bucket, e invia un ultimo pacchetto.

Verifica, in un terminale:
    sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152
Verifica, nell'altro terminale, i contatori del loader Rust (drop QoS).
"""
import time
from scapy.all import IP, UDP, Raw, send
from netns_topology import UE_IP

UE_PORT = 3000

def main():
    # Creazione del pacchetto IP interno (36 byte totali: 20 IP + 8 UDP + 8 Raw)
    pkt = IP(dst=UE_IP) / UDP(sport=6000, dport=UE_PORT) / Raw(b"hello-ue")

    print("==================================================")
    print(" FASE 1: Raffica di 5 pacchetti (Saturazione QoS)")
    print("==================================================")
    # Inviamo 5 pacchetti distanziati di soli 10ms.
    # Se il burst_dl è 80 byte e il pacchetto pesa 36 byte:
    # - Pkt 1 (Passa, restano 64 byte)
    # - Pkt 2 (Passa, restano 28 byte)
    # - Pkt 3, 4, 5 (DROP per QoS, token insufficienti)
    for i in range(5):
        send(pkt, verbose=False)
        print(f"[{i+1}/5] Pacchetto inviato verso l'UE...")
        time.sleep(0.01)

    print("\n==================================================")
    print(" FASE 2: Attesa di 2 secondi (Ricarica Token)")
    print("==================================================")
    # A 50 byte/s, 2 secondi ricaricano 100 byte (capienza massima)
    for i in range(2, 0, -1):
        print(f"Attesa... {i}s")
        time.sleep(1.0)

    print("\n==================================================")
    print(" FASE 3: Pacchetto Post-Ricarica (Dovrebbe passare)")
    print("==================================================")
    # Il secchio è di nuovo pieno, questo pacchetto deve passare
    send(pkt, verbose=False)
    print("[6/6] Pacchetto finale inviato! Controlla tcpdump e i contatori.\n")

if __name__ == "__main__":
    main()