#!/usr/bin/env python3
"""
Test live del Control Plane UDP (mini-PFCP) della UPF.
Eseguire sull'host con sudo mentre upf_simply è attiva in Uplink (veth-n3 -> veth-n6).
"""
import argparse
import json
import socket
import struct
import subprocess
import sys
import time

CP_ADDR = ("127.0.0.1", 8805)
GNB_NS = "ns-gnb"
DN_NS = "ns-dn"
DN_IFACE = "veth-dn"
UPF_N3_IP = "10.0.3.1"
UE_IP = "10.60.0.1"
DN_IP = "10.0.6.2"
INNER_SPORT = 4000
INNER_DPORT = 5000


def ipv4_checksum(header: bytes) -> int:
    s = sum(struct.unpack("!10H", header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_gtpu_payload(teid: int, qfi: int = 9, inner_ip_len: int = 1000) -> bytes:
    """Costruisce GTP-U (flags 0x34 + PDU Session Container 0x85) + IPv4/UDP interno."""
    payload_len = inner_ip_len - 20 - 8
    inner_payload = b"A" * payload_len

    # Inner UDP (checksum=0 valido in IPv4)
    inner_udp = struct.pack("!HHHH", INNER_SPORT, INNER_DPORT, 8 + payload_len, 0)

    # Inner IPv4 (IHL=5, TOS=0x00)
    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, inner_ip_len, 0x1234, 0x0000, 64, 17, 0,
        socket.inet_aton(UE_IP), socket.inet_aton(DN_IP),
    )
    csum = ipv4_checksum(ip_no_csum)
    inner_ip = ip_no_csum[:10] + struct.pack("!H", csum) + ip_no_csum[12:] + inner_udp + inner_payload

    # GTP-U v1 con Extension Header 0x85 (UL PDU Session Container, PDU Type = 1)
    # Length GTP = 4 (opt hdr) + 4 (ext hdr) + len(inner_ip)
    gtp_hdr = struct.pack(
        "!BBHIHBBBBBB",
        0x34,                # Version 1, PT=1, E=1
        0xFF,                # G-PDU
        8 + len(inner_ip),   # Length
        teid,                # TEID
        0x0000,              # Sequence Number
        0x00,                # N-PDU
        0x85,                # Next Ext Hdr: PDU Session Container
        0x01,                # Ext Hdr Length (1 * 4B)
        0x10,                # PDU Type = 1 (UL)
        qfi & 0x3F,          # QFI
        0x00,                # No more ext hdrs
    )
    return gtp_hdr + inner_ip


def worker_tx(teid: int, qfi: int, rate_mbps: float, duration: float, count: int):
    """Invia traffico GTP-U dall'interno di ns-gnb verso UPF_N3_IP:2152."""
    pkt = build_gtpu_payload(teid=teid, qfi=qfi, inner_ip_len=1000)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (UPF_N3_IP, 2152)

    if count > 0:
        for _ in range(count):
            sock.sendto(pkt, dst)
            time.sleep(0.01)
        return

    # Pacing software basato sui byte dell'IP interno (1000 B)
    pps = (rate_mbps * 1_000_000) / (8.0 * 1000.0)
    interval = 1.0 / pps
    start = time.perf_counter()
    end = start + duration
    next_t = start
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        if now >= next_t:
            sock.sendto(pkt, dst)
            next_t += interval


def worker_rx(duration: float):
    """Cattura i pacchetti IPv4 decapsulati su veth-dn dentro ns-dn."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((DN_IFACE, 0))
    sock.settimeout(0.2)

    target_dst = socket.inet_aton(DN_IP)
    end = time.monotonic() + duration
    pkts = 0
    total_bytes = 0
    green = 0
    yellow = 0

    while time.monotonic() < end:
        try:
            frame = sock.recv(2048)
        except socket.timeout:
            continue
        if len(frame) < 14 + 28:
            continue
        ip = frame[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 8 or ip[16:20] != target_dst:
            continue
        dport = struct.unpack("!H", ip[ihl + 2 : ihl + 4])[0]
        if dport != INNER_DPORT:
            continue

        ip_len = struct.unpack("!H", ip[2:4])[0]
        tos = ip[1]
        pkts += 1
        total_bytes += ip_len
        if tos == 0x00:
            green += 1
        elif tos == 0x38:
            yellow += 1

    print(json.dumps({"pkts": pkts, "bytes": total_bytes, "green": green, "yellow": yellow}))


def send_cp(raw_payload: str) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sock.sendto(raw_payload.encode(), CP_ADDR)
    data, _ = sock.recvfrom(4096)
    sock.close()
    resp = json.loads(data.decode())
    print(f"  -> CP TX: {raw_payload}")
    print(f"  <- CP RX: {resp}")
    return resp


def run_burst_probe(teid: int, count: int = 20) -> dict:
    """Invia `count` pacchetti su `teid` e misura quanti escono decapsulati in ns-dn."""
    rx = subprocess.Popen(
        ["ip", "netns", "exec", DN_NS, sys.executable, __file__, "--worker-rx", "--duration", "1.2"],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        [
            "taskset", "-c", "2", "ip", "netns", "exec", GNB_NS,
            sys.executable, __file__, "--worker-tx",
            "--teid", str(teid), "--count", str(count),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=5)
    return json.loads(out.strip())


def run_rate_measure(teid: int, offer_mbps: float, duration: float = 3.0) -> tuple[float, dict]:
    """Invia traffico continuo a `offer_mbps` per `duration` s e calcola il throughput in uscita."""
    rx = subprocess.Popen(
        ["ip", "netns", "exec", DN_NS, sys.executable, __file__, "--worker-rx", "--duration", str(duration + 0.4)],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        [
            "taskset", "-c", "2", "ip", "netns", "exec", GNB_NS,
            sys.executable, __file__, "--worker-tx",
            "--teid", str(teid), "--rate", str(offer_mbps), "--duration", str(duration),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=duration + 5)
    stats = json.loads(out.strip())
    mbps = (stats["bytes"] * 8.0) / (duration * 1_000_000.0)
    return mbps, stats


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker-tx", action="store_true")
    p.add_argument("--worker-rx", action="store_true")
    p.add_argument("--teid", type=int, default=5555)
    p.add_argument("--qfi", type=int, default=9)
    p.add_argument("--rate", type=float, default=15.0)
    p.add_argument("--duration", type=float, default=3.0)
    p.add_argument("--count", type=int, default=0)
    args = p.parse_args()

    if args.worker_tx:
        worker_tx(args.teid, args.qfi, args.rate, args.duration, args.count)
        return
    if args.worker_rx:
        worker_rx(args.duration)
        return

    ok_all = True
    def check(label: str, cond: bool, detail: str = ""):
        nonlocal ok_all
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok_all = False
        print(f"[{status}] {label} {detail}")

    print("\n=== TEST 1: Robustezza errori (JSON rotto + QoS invalida) ===")
    r1 = send_cp('{"cmd":"add_uplink","teid":"non_valido"}')
    check("JSON malformato rifiutato", r1.get("ok") is False)
    r2 = send_cp(json.dumps({
        "cmd": "add_uplink", "teid": 6666, "far_id": 11,
        "qos": {"qer_id": 11, "qfi": 5, "gbr_mbps": 30, "mbr_mbps": 10},
    }))
    check("GBR > MBR rifiutato", r2.get("ok") is False)

    print("\n=== TEST 2: Creazione sessione live (TEID 5555) ===")
    before = run_burst_probe(teid=5555, count=20)
    check("Prima di add_uplink: nessun pacchetto decapsulato", before["pkts"] == 0, f"(rx={before['pkts']})")

    r3 = send_cp(json.dumps({
        "cmd": "add_uplink", "teid": 5555, "far_id": 10, "far_action": "forward",
        "qos": {"qer_id": 10, "qfi": 9, "gbr_mbps": 10, "mbr_mbps": 20, "burst_bytes": 15000},
    }))
    check("add_uplink TEID 5555 accettato", r3.get("ok") is True)

    after = run_burst_probe(teid=5555, count=20)
    check("Dopo add_uplink: tutti i 20 pacchetti decapsulati", after["pkts"] == 20, f"(rx={after['pkts']})")

    print("\n=== TEST 3: Cambio banda live (update_qer 20 Mbps -> 2 Mbps) ===")
    mbps_hi, st_hi = run_rate_measure(teid=5555, offer_mbps=15.0, duration=3.0)
    check("Con MBR=20, flusso a 15 Mbps passa quasi intatto", mbps_hi > 11.0,
          f"(rx={mbps_hi:.2f} Mbps, green={st_hi['green']}, yellow={st_hi['yellow']})")

    r4 = send_cp(json.dumps({
        "cmd": "update_qer", "qer_id": 10, "qfi": 9,
        "gbr_ul_mbps": 1, "mbr_ul_mbps": 2,
    }))
    check("update_qer a GBR=1 / MBR=2 accettato", r4.get("ok") is True)

    mbps_lo, st_lo = run_rate_measure(teid=5555, offer_mbps=15.0, duration=3.0)
    check("Dopo update_qer, throughput tagliato a ~2 Mbps", 1.5 <= mbps_lo <= 2.6,
          f"(rx={mbps_lo:.2f} Mbps, green={st_lo['green']}, yellow={st_lo['yellow']})")

    print("\n=== TEST 4: Rilascio sessione (delete_uplink TEID 5555) ===")
    r5 = send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5555}))
    check("delete_uplink TEID 5555 accettato", r5.get("ok") is True)

    after_del = run_burst_probe(teid=5555, count=20)
    check("Dopo delete_uplink: nessun pacchetto decapsulato", after_del["pkts"] == 0, f"(rx={after_del['pkts']})")

    r6 = send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5555}))
    check("Seconda delete_uplink restituisce errore (PDR non trovata)", r6.get("ok") is False)

    print("\n" + ("=== TUTTI I TEST SUPERATI ===" if ok_all else "=== ALCUNI TEST FALLITI ==="))
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()