"""
Test della INCAPSULAZIONE downlink e RATE LIMITING (GCRA/Per-CPU).

Va eseguito DENTRO ns-dn:
    sudo ip netns exec ns-dn python3 netns_qos_dl_test.py

Il test sfrutta l'invio grezzo a livello di socket per abbattere le
latenze di Scapy e misurare la reale applicazione del GCRA nell'XDP.

Verifica, in un terminale:
    sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152
Verifica, nell'altro terminale, i contatori del loader Rust (drop QoS).
"""

import time
import socket
from scapy.all import IP, UDP, Raw

UE_IP = "10.60.0.1"
UE_PORT = 3000

def main():
    # 20 byte (IP) + 8 byte (UDP) + 8 byte (Raw) = 36 byte
    pkt = IP(dst=UE_IP) / UDP(sport=6000, dport=UE_PORT) / Raw(b"hello-ue")
    raw_pkt = bytes(pkt)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    print("==================================================")
    print(" FASE 1: Raffica Raw Socket (Saturazione GCRA)")
    print("==================================================")
    
    # Invia 15 pacchetti consecutivi senza delay
    burst_count = 15
    start_time = time.perf_counter()
    for _ in range(burst_count):
        s.sendto(raw_pkt, (UE_IP, 0))
    end_time = time.perf_counter()
    
    print(f"[{burst_count}/{burst_count}] Pacchetti inviati in {(end_time - start_time)*1000:.2f} ms")
    
    print("\n==================================================")
    print(" FASE 2: Pausa per il reset del Theoretical Arrival Time")
    print("==================================================")
    # 1 secondo è sufficiente per riazzerare il debito temporale
    time.sleep(1.0)

    print("==================================================")
    print(" FASE 3: Pacchetto di recupero")
    print("==================================================")
    s.sendto(raw_pkt, (UE_IP, 0))
    print("[16/16] Pacchetto finale inviato. Controlla tcpdump e i log di upf_simply.")

if __name__ == "__main__":
    main()