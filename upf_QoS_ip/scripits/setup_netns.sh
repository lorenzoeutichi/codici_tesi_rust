#!/usr/bin/env bash
# Topologia di test per upf_simply: gNB -- (N3) -- UPF (root ns) -- (N6) -- DN
#
#   ns-gnb                      root ns (UPF)                    ns-dn
#   veth-gnb ===== veth-n3                    veth-n6 ===== veth-dn
#   10.0.3.2/30    10.0.3.1/30                10.0.6.1/30   10.0.6.2/30
#   MAC ..03:02    MAC ..03:01                MAC ..06:01   MAC ..06:02
#
# Il programma XDP di upf_simply va agganciato a veth-n3 (uplink, decap) e
# veth-n6 (downlink, encap), nella root namespace.
#
# Uso:
#   sudo ./setup_netns.sh up       # crea la topologia (idempotente)
#   sudo ./setup_netns.sh down     # la rimuove
#   sudo ./setup_netns.sh status   # mostra IP/MAC correnti
#
# Dopo "up", lancia il loader nella root ns, ad esempio:
#   sudo -E RUST_LOG=info ./target/release/upf_simply --iface veth-n3
# (adatta il comando alle opzioni reali del tuo loader, specialmente se
# aggancia una sola interfaccia alla volta o entrambe in un colpo solo)

set -euo pipefail

NS_GNB=ns-gnb
NS_DN=ns-dn

V_GNB=veth-gnb      # dentro ns-gnb
V_N3=veth-n3        # dentro root ns, lato gNB
V_DN=veth-dn        # dentro ns-dn
V_N6=veth-n6        # dentro root ns, lato DN

MAC_GNB=02:00:00:00:03:02
MAC_N3=02:00:00:00:03:01
MAC_DN=02:00:00:00:06:02
MAC_N6=02:00:00:00:06:01

IP_GNB=10.0.3.2/30
IP_N3=10.0.3.1/30
IP_DN=10.0.6.2/30
IP_N6=10.0.6.1/30

UE_SUBNET=10.60.0.0/16

down() {
    ip netns del "$NS_GNB" 2>/dev/null || true
    ip netns del "$NS_DN" 2>/dev/null || true
    ip link del "$V_N3" 2>/dev/null || true
    ip link del "$V_N6" 2>/dev/null || true
    echo "Topologia rimossa (se esisteva)."
}

up() {
    down   # idempotente: riparte sempre da zero

    ip netns add "$NS_GNB"
    ip netns add "$NS_DN"

    # --- N3: gNB <-> UPF ---
    ip link add "$V_N3" type veth peer name "$V_GNB" netns "$NS_GNB"
    ip link set "$V_N3" address "$MAC_N3"
    ip netns exec "$NS_GNB" ip link set "$V_GNB" address "$MAC_GNB"

    ip addr add "$IP_N3" dev "$V_N3"
    ip netns exec "$NS_GNB" ip addr add "$IP_GNB" dev "$V_GNB"

    ip link set "$V_N3" up
    ip netns exec "$NS_GNB" ip link set "$V_GNB" up
    ip netns exec "$NS_GNB" ip link set lo up

    # --- N6: UPF <-> DN ---
    ip link add "$V_N6" type veth peer name "$V_DN" netns "$NS_DN"
    ip link set "$V_N6" address "$MAC_N6"
    ip netns exec "$NS_DN" ip link set "$V_DN" address "$MAC_DN"

    ip addr add "$IP_N6" dev "$V_N6"
    ip netns exec "$NS_DN" ip addr add "$IP_DN" dev "$V_DN"

    ip link set "$V_N6" up
    ip netns exec "$NS_DN" ip link set "$V_DN" up
    ip netns exec "$NS_DN" ip link set lo up

    # Route per la subnet degli UE nella DN: senza, la DN non sa rispondere
    # ai pacchetti decapsulati che arrivano con sorgente 10.60.x.x.
    ip netns exec "$NS_DN" ip route add "$UE_SUBNET" via "${IP_N6%/*}" dev "$V_DN"

    # Forwarding nella root ns (UPF)
    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv4.conf.all.rp_filter=0
    sysctl -qw "net.ipv4.conf.$V_N3.rp_filter=0"
    sysctl -qw "net.ipv4.conf.$V_N6.rp_filter=0"
    # L'IP sorgente che l'UPF userà per l'header esterno incapsulato (IP_N3)
    # non appartiene alla subnet di N6: senza accept_local il kernel lo
    # scarta come "martian source" quando esce da veth-n6.
    sysctl -qw "net.ipv4.conf.$V_N6.accept_local=1"
    sysctl -qw net.ipv4.conf.all.log_martians=1

    # Spegni l'offload dei checksum sulle veth: altrimenti i pacchetti che il
    # kernel genera possono apparire con checksum "sbagliato" solo perché il
    # calcolo è delegato (a una NIC che qui non esiste).
    for i in "$V_N3" "$V_N6"; do
        ethtool -K "$i" tx off rx off 2>/dev/null || true
    done
    ip netns exec "$NS_GNB" ethtool -K "$V_GNB" tx off rx off 2>/dev/null || true
    ip netns exec "$NS_DN" ethtool -K "$V_DN" tx off rx off 2>/dev/null || true

    echo "Topologia creata."
    status
}

status() {
    printf "\n%-10s %-10s %-12s %-18s\n" "ns" "iface" "ip" "mac"
    printf "%-10s %-10s %-12s %-18s\n" "root" "$V_N3" "$IP_N3" "$MAC_N3"
    printf "%-10s %-10s %-12s %-18s\n" "root" "$V_N6" "$IP_N6" "$MAC_N6"
    printf "%-10s %-10s %-12s %-18s\n" "$NS_GNB" "$V_GNB" "$IP_GNB" "$MAC_GNB"
    printf "%-10s %-10s %-12s %-18s\n" "$NS_DN" "$V_DN" "$IP_DN" "$MAC_DN"
    echo
    echo "UE subnet instradata nella DN: $UE_SUBNET via ${IP_N6%/*}"
    echo
    echo "Esempi d'uso:"
    echo "  sudo ip netns exec $NS_GNB python3 netns_decap_test.py"
    echo "  sudo ip netns exec $NS_DN  python3 netns_encap_test.py"
    echo "  sudo ip netns exec $NS_GNB python3 gtp_watch.py --iface $V_GNB"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "Uso: $0 {up|down|status}"; exit 1 ;;
esac