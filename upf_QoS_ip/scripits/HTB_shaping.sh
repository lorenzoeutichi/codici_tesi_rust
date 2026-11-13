#!/bin/bash

IFACE=${1:-veth-n6}

echo "Configurazione HTB Token Bucket Shaping sull'interfaccia $IFACE"

# 1. Pulizia configurazioni precedenti
sudo tc qdisc del dev $IFACE root 2>/dev/null

# 2. Creazione della qdisc root HTB
# Il parametro default 20 instrada il traffico non filtrato alla coda Gialla/Bassa priorità
sudo tc qdisc add dev $IFACE root handle 1: htb default 20

# 3. Creazione delle Classi HTB (I veri Token Bucket)
# Classe Padre 1:1 (es. Limite totale dell'interfaccia o del tunnel)
sudo tc class add dev $IFACE parent 1: classid 1:1 htb rate 100mbit ceil 100mbit

# Coda 1 (1:10) (Alta Priorità / VERDE - DSCP 0x00)
# Banda garantita (rate) al 100%. Può assorbire burst tramite il parametro burst.
sudo tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit burst 15000b

# Coda 2 (1:20) (Bassa Priorità / GIALLO - DSCP 0x38 / AF13)
# Banda garantita molto bassa o nulla (rate), ma può salire (ceil) solo se la coda Verde non sta consumando.
sudo tc class add dev $IFACE parent 1:1 classid 1:20 htb rate 1mbit ceil 100mbit burst 1600b

# (Opzionale ma raccomandato) Aggiungere qdisc fq_codel alle foglie per gestire meglio i microburst e la latenza
sudo tc qdisc add dev $IFACE parent 1:10 handle 10: fq_codel
sudo tc qdisc add dev $IFACE parent 1:20 handle 20: fq_codel

# 4. Filtri (U32) per instradare in base al DSCP marcato da XDP
# Filtro 1 (Traffico Verde): TOS == 0x00 -> Coda HTB 1:10 (Alta priorità)
sudo tc filter add dev $IFACE protocol ip parent 1:0 prio 1 u32 match ip tos 0x00 0xff flowid 1:10

# Filtro 2 (Traffico Giallo): TOS == 0x38 -> Coda HTB 1:20 (Bassa priorità)
sudo tc filter add dev $IFACE protocol ip parent 1:0 prio 2 u32 match ip tos 0x38 0xff flowid 1:20

echo "Configurazione completata. Verifica lo stato con:"
echo "sudo tc -s class show dev $IFACE"