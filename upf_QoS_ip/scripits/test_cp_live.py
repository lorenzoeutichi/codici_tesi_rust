#!/usr/bin/env python3
"""
Test live del Control Plane UDP (mini-PFCP) della UPF Full-Duplex.
Valida gestione errori (inclusi vincoli 5QI/QFI), ciclo di vita sessioni UL/DL,
cambio banda live, declassamento a Non-QoS, ramo Non-QoS puro, anti-spoofing TOS,
isolamento parallelo e mappatura multi-classe 3GPP/RFC 4594/GSMA IR.34.

Eseguire sull'host con sudo mentre upf_simply e' attiva in Full-Duplex:
    sudo python3 scripts/test_cp_live.py --mbr-ul 20 --gbr-ul 10 --non-qos-rate 10 --ef-rate 20
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

CP_ADDR = ("127.0.0.1", 8805)
GNB_NS = "ns-gnb"
DN_NS = "ns-dn"
GNB_IFACE = "veth-gnb"
DN_IFACE = "veth-dn"
UPF_N3_IP = "10.0.3.1"
GNB_N3_IP = "10.0.3.2"
UE_IP = "10.60.0.1"
UE_DL_NONQOS = "10.60.0.2"
DN_IP = "10.0.6.2"
INNER_SPORT = 4000
INNER_DPORT = 5000
DL_DPORT = 6000
GTP_PORT = 2152

# Byte TOS (DSCP << 2) secondo 3GPP TS 23.501 + RFC 4594 / GSMA IR.34
TOS_EF = 0xB8     # 5QI 1, 3, 65, 82..85  -> 1:10
TOS_CS5 = 0xA0    # 5QI 5, 69             -> 1:10
TOS_AF41 = 0x88   # 5QI 2, 67 (Verde)     -> 1:21
TOS_AF43 = 0x98   # 5QI 2, 67 (Giallo)    -> 1:22
TOS_AF31 = 0x68   # 5QI 4, 66 (Verde)     -> 1:31
TOS_AF33 = 0x78   # 5QI 4, 66 (Giallo)    -> 1:32
TOS_AF11 = 0x28   # 5QI 6, 7, 8 (Non-GBR) -> 1:41
TOS_BE = 0x00     # 5QI 9 / qos=null      -> 1:42


def ipv4_checksum(header: bytes) -> int:
    s = sum(struct.unpack("!10H", header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_csum_ok(hdr: bytes) -> bool:
    s = sum(struct.unpack(f"!{len(hdr) // 2}H", hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def cpu_pin(preferred: int) -> list[str]:
    n = os.cpu_count() or 1
    return ["taskset", "-c", str(preferred % n)]


def build_gtpu_payload(
    teid: int,
    qfi: int = 9,
    inner_ip_len: int = 1000,
    inner_tos: int = 0x00,
    sport: int = INNER_SPORT,
) -> bytes:
    """Costruisce GTP-U (flags 0x34 + PDU Session Container 0x85) + IPv4/UDP interno."""
    payload_len = inner_ip_len - 20 - 8
    inner_payload = b"A" * payload_len

    inner_udp = struct.pack("!HHHH", sport, INNER_DPORT, 8 + payload_len, 0)

    ip_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, inner_tos, inner_ip_len, 0x1234, 0x0000, 64, 17, 0,
        socket.inet_aton(UE_IP), socket.inet_aton(DN_IP),
    )
    csum = ipv4_checksum(ip_no_csum)
    inner_ip = ip_no_csum[:10] + struct.pack("!H", csum) + ip_no_csum[12:] + inner_udp + inner_payload

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


def count_by_tos(samples: list[tuple[float, int, int]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for _, _, tos in samples:
        k = f"0x{tos:02x}"
        counts[k] = counts.get(k, 0) + 1
    return counts


def compute_window_stats(samples: list[tuple[float, int, int]], tx_dur: float, warm: float, tail: float) -> dict:
    """Calcola throughput e distribuzione TOS nella finestra a regime [t0 + warm, t0 + tx_dur - tail]."""
    if not samples or tx_dur <= 0:
        return {"mbps": 0.0, "pkts": 0, "green": 0, "yellow": 0, "non_qos": 0, "tos_counts": {}}
    t0 = samples[0][0]
    a, b = t0 + warm, t0 + tx_dur - tail
    if b <= a + 0.1:
        total_b = sum(x[1] for x in samples)
        tc = count_by_tos(samples)
        return {
            "mbps": (total_b * 8.0) / (tx_dur * 1_000_000.0),
            "pkts": len(samples),
            "green": tc.get("0x88", 0),
            "yellow": tc.get("0x98", 0),
            "non_qos": tc.get("0x00", 0),
            "tos_counts": tc,
        }
    sel = [x for x in samples if a <= x[0] <= b]
    win_bytes = sum(x[1] for x in sel)
    tc = count_by_tos(sel)
    return {
        "mbps": (win_bytes * 8.0) / ((b - a) * 1_000_000.0),
        "pkts": len(sel),
        "green": tc.get("0x88", 0),
        "yellow": tc.get("0x98", 0),
        "non_qos": tc.get("0x00", 0),
        "tos_counts": tc,
    }


def worker_tx(
    teid: int,
    qfi: int,
    rate_mbps: float,
    duration: float,
    count: int,
    inner_tos: int,
    sport: int,
):
    """Invia traffico GTP-U dall'interno di ns-gnb verso UPF_N3_IP:2152."""
    pkt = build_gtpu_payload(
        teid=teid, qfi=qfi, inner_ip_len=1000, inner_tos=inner_tos, sport=sport
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (UPF_N3_IP, GTP_PORT)

    if count > 0:
        for _ in range(count):
            sock.sendto(pkt, dst)
            time.sleep(0.01)
        return

    pps = (rate_mbps * 1_000_000) / (8.0 * 1000.0)
    t0 = time.perf_counter()
    end = t0 + duration
    n = 0
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        due = int((now - t0) * pps) + 1
        while n < due:
            sock.sendto(pkt, dst)
            n += 1
        time.sleep(0.0002)


def worker_tx_parallel(
    qos_teid: int,
    qos_rate: float,
    nonqos_teid: int,
    nonqos_rate: float,
    duration: float,
):
    """Invia due flussi GTP-U interleaved sullo stesso socket e stessa CPU (CPU 2)."""
    pkt_qos = build_gtpu_payload(
        teid=qos_teid, qfi=5, inner_ip_len=1000, inner_tos=0x00, sport=4001
    )
    pkt_nq = build_gtpu_payload(
        teid=nonqos_teid, qfi=9, inner_ip_len=1000, inner_tos=TOS_AF41, sport=4002
    )
    flows = [
        (pkt_qos, (qos_rate * 1_000_000) / (8.0 * 1000.0)),
        (pkt_nq, (nonqos_rate * 1_000_000) / (8.0 * 1000.0)),
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (UPF_N3_IP, GTP_PORT)

    t0 = time.perf_counter()
    end = t0 + duration
    sent = [0, 0]
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        elapsed = now - t0
        progressed = False
        for i, (pkt, pps) in enumerate(flows):
            due = int(elapsed * pps) + 1
            if sent[i] < due:
                sock.sendto(pkt, dst)
                sent[i] += 1
                progressed = True
        if not progressed:
            time.sleep(0.0002)


def worker_rx(duration: float, tx_dur: float, warm: float, tail: float):
    """Cattura i pacchetti IPv4 decapsulati su veth-dn dentro ns-dn."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((DN_IFACE, 0))
    sock.settimeout(0.2)

    target_dst = socket.inet_aton(DN_IP)
    end = time.monotonic() + duration

    def empty_bucket():
        return {
            "pkts": 0, "bytes": 0,
            "green": 0, "yellow": 0, "non_qos": 0, "other_tos": 0, "bad_csum": 0,
            "tos_counts": {},
        }

    tot = empty_bucket()
    by_sport: dict[str, dict] = {}
    tot_samples: list[tuple[float, int, int]] = []
    sport_samples: dict[str, list[tuple[float, int, int]]] = {}

    while time.monotonic() < end:
        try:
            frame = sock.recv(2048)
        except socket.timeout:
            continue
        now = time.monotonic()
        if len(frame) < 14 + 28:
            continue
        ip = frame[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 8 or ip[16:20] != target_dst:
            continue
        sport, dport = struct.unpack("!HH", ip[ihl : ihl + 4])
        if dport != INNER_DPORT:
            continue

        ip_len = struct.unpack("!H", ip[2:4])[0]
        tos = ip[1] & 0xFC
        tkey = f"0x{tos:02x}"
        csum_bad = not ip_csum_ok(ip[:ihl])

        skey = str(sport)
        if skey not in by_sport:
            by_sport[skey] = empty_bucket()
            sport_samples[skey] = []

        tot_samples.append((now, ip_len, tos))
        sport_samples[skey].append((now, ip_len, tos))

        for b in (tot, by_sport[skey]):
            b["pkts"] += 1
            b["bytes"] += ip_len
            b["tos_counts"][tkey] = b["tos_counts"].get(tkey, 0) + 1
            if csum_bad:
                b["bad_csum"] += 1
            if tos == TOS_AF41:
                b["green"] += 1
            elif tos == TOS_AF43:
                b["yellow"] += 1
            elif tos == TOS_BE:
                b["non_qos"] += 1
            else:
                b["other_tos"] += 1

    tot["steady"] = compute_window_stats(tot_samples, tx_dur, warm, tail)
    for skey, b in by_sport.items():
        b["steady"] = compute_window_stats(sport_samples[skey], tx_dur, warm, tail)
    tot["by_sport"] = by_sport
    print(json.dumps(tot))


def worker_tx_dl(ue_ip: str, rate_mbps: float, duration: float, count: int, inner_tos: int):
    """Invia traffico IPv4/UDP 'nudo' dall'interno di ns-dn verso ue_ip:DL_DPORT."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, inner_tos)
    payload = b"D" * (1000 - 20 - 8)
    dst = (ue_ip, DL_DPORT)

    if count > 0:
        for _ in range(count):
            sock.sendto(payload, dst)
            time.sleep(0.01)
        return

    pps = (rate_mbps * 1_000_000) / (8.0 * 1000.0)
    t0 = time.perf_counter()
    end = t0 + duration
    n = 0
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        due = int((now - t0) * pps) + 1
        while n < due:
            sock.sendto(payload, dst)
            n += 1
        time.sleep(0.0002)


def worker_rx_dl(duration: float, target_teid: int, tx_dur: float, warm: float, tail: float):
    """Cattura i pacchetti GTP-U incapsulati su veth-gnb dentro ns-gnb."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((GNB_IFACE, 0))
    sock.settimeout(0.2)

    end = time.monotonic() + duration
    res = {
        "pkts": 0, "inner_bytes": 0,
        "green": 0, "yellow": 0, "non_qos": 0, "other_tos": 0,
        "bad_outer_csum": 0, "qfis": {}, "tos_counts": {},
    }
    samples: list[tuple[float, int, int]] = []

    while time.monotonic() < end:
        try:
            frame = sock.recv(2048)
        except socket.timeout:
            continue
        now = time.monotonic()
        if len(frame) < 14 + 20 + 8 + 16:
            continue
        ip = frame[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        udp = ip[ihl:]
        if len(udp) < 8 + 16:
            continue
        dport = struct.unpack("!H", udp[2:4])[0]
        if dport != GTP_PORT:
            continue
        gtp = udp[8:]
        flags, mtype, _glen, teid = struct.unpack("!BBHI", gtp[:8])
        if mtype != 255 or teid != target_teid:
            continue

        qfi = None
        off = 8
        if flags & 0x07:
            next_t = gtp[11]
            off = 12
            while next_t != 0 and off + 4 <= len(gtp):
                elen = gtp[off] * 4
                if elen == 0:
                    break
                if next_t == 0x85 and elen >= 4:
                    qfi = gtp[off + 2] & 0x3F
                next_t = gtp[off + elen - 1]
                off += elen

        inner = gtp[off:]
        inner_len = struct.unpack("!H", inner[2:4])[0] if len(inner) >= 4 else 0
        tos = ip[1] & 0xFC
        tkey = f"0x{tos:02x}"

        samples.append((now, inner_len, tos))
        res["pkts"] += 1
        res["inner_bytes"] += inner_len
        res["tos_counts"][tkey] = res["tos_counts"].get(tkey, 0) + 1
        if not ip_csum_ok(ip[:ihl]):
            res["bad_outer_csum"] += 1
        if tos == TOS_AF41:
            res["green"] += 1
        elif tos == TOS_AF43:
            res["yellow"] += 1
        elif tos == TOS_BE:
            res["non_qos"] += 1
        else:
            res["other_tos"] += 1
        qkey = str(qfi)
        res["qfis"][qkey] = res["qfis"].get(qkey, 0) + 1

    res["steady"] = compute_window_stats(samples, tx_dur, warm, tail)
    print(json.dumps(res))


def tc_state(iface: str) -> tuple[dict[str, int], dict[str, int]]:
    """Ritorna ({classid: sent_pkts}, {classid: backlog_pkts}) da `tc -s class show`."""
    try:
        txt = subprocess.run(
            ["tc", "-s", "class", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return {}, {}
    sent, backlog = {}, {}
    for blk in txt.split("class htb ")[1:]:
        cid = blk.split()[0]
        m = re.search(r"Sent (\d+) bytes (\d+) pkt", blk)
        if m:
            sent[cid] = int(m.group(2))
        b = re.search(r"backlog \d+\w* (\d+)p", blk)
        if b:
            backlog[cid] = int(b.group(1))
    return sent, backlog


def tc_classes(iface: str) -> dict[str, int]:
    return tc_state(iface)[0]


def tc_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {c: after.get(c, 0) - before.get(c, 0) for c in after}


def wait_tc_drain(iface: str, classid: str = "1:42", timeout: float = 15.0):
    """Attende che il backlog della classe TC (es. fq_codel 42:) si svuoti completamente."""
    t0 = time.monotonic()
    prev = tc_state(iface)[0].get(classid, 0)
    stable = 0
    while time.monotonic() - t0 < timeout:
        time.sleep(0.25)
        sent, backlog = tc_state(iface)
        cur = sent.get(classid, 0)
        bl = backlog.get(classid, 0)
        if bl == 0 and cur == prev:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
            prev = cur
    elapsed = time.monotonic() - t0
    if elapsed > 0.8:
        print(f"  (drain coda TC {iface} [{classid}] completato in {elapsed:.1f}s)")
    time.sleep(0.2)


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


def run_burst_probe(
    teid: int, count: int = 20, inner_tos: int = 0x00, tc_if: str | None = None, qfi: int = 9
) -> tuple[dict, dict]:
    before = tc_classes(tc_if) if tc_if else {}
    rx = subprocess.Popen(
        [
            "ip", "netns", "exec", DN_NS, sys.executable, __file__,
            "--worker-rx", "--duration", "1.2", "--tx-dur", "0",
        ],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        cpu_pin(2) + [
            "ip", "netns", "exec", GNB_NS,
            sys.executable, __file__, "--worker-tx",
            "--teid", str(teid), "--qfi", str(qfi),
            "--count", str(count), "--inner-tos", str(inner_tos),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=5)
    after = tc_classes(tc_if) if tc_if else {}
    return json.loads(out.strip()), tc_delta(before, after)


def run_rate_measure(
    teid: int,
    offer_mbps: float,
    duration: float = 3.5,
    inner_tos: int = 0x00,
    tc_if: str | None = None,
    warm: float = 0.8,
    tail: float = 0.3,
    qfi: int = 9,
) -> tuple[float, dict, dict]:
    before = tc_classes(tc_if) if tc_if else {}
    rx = subprocess.Popen(
        [
            "ip", "netns", "exec", DN_NS, sys.executable, __file__,
            "--worker-rx", "--duration", str(duration + 0.5),
            "--tx-dur", str(duration), "--warm", str(warm), "--tail", str(tail),
        ],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        cpu_pin(2) + [
            "ip", "netns", "exec", GNB_NS,
            sys.executable, __file__, "--worker-tx",
            "--teid", str(teid), "--qfi", str(qfi),
            "--rate", str(offer_mbps), "--duration", str(duration),
            "--inner-tos", str(inner_tos),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=duration + 5)
    after = tc_classes(tc_if) if tc_if else {}
    stats = json.loads(out.strip())
    return stats["steady"]["mbps"], stats, tc_delta(before, after)


def run_dl_probe(
    ue_ip: str, target_teid: int, count: int = 20, inner_tos: int = 0x00, tc_if: str | None = None
) -> tuple[dict, dict]:
    before = tc_classes(tc_if) if tc_if else {}
    rx = subprocess.Popen(
        [
            "ip", "netns", "exec", GNB_NS, sys.executable, __file__,
            "--worker-rx-dl", "--duration", "1.2", "--tx-dur", "0", "--teid", str(target_teid),
        ],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        cpu_pin(2) + [
            "ip", "netns", "exec", DN_NS, sys.executable, __file__,
            "--worker-tx-dl", "--ue-ip", ue_ip,
            "--count", str(count), "--inner-tos", str(inner_tos),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=5)
    after = tc_classes(tc_if) if tc_if else {}
    return json.loads(out.strip()), tc_delta(before, after)


def run_dl_rate_measure(
    ue_ip: str,
    target_teid: int,
    offer_mbps: float,
    duration: float = 3.5,
    inner_tos: int = 0x00,
    tc_if: str | None = None,
    warm: float = 0.8,
    tail: float = 0.3,
) -> tuple[float, dict, dict]:
    before = tc_classes(tc_if) if tc_if else {}
    rx = subprocess.Popen(
        [
            "ip", "netns", "exec", GNB_NS, sys.executable, __file__,
            "--worker-rx-dl", "--duration", str(duration + 0.5),
            "--tx-dur", str(duration), "--warm", str(warm), "--tail", str(tail),
            "--teid", str(target_teid),
        ],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        cpu_pin(2) + [
            "ip", "netns", "exec", DN_NS, sys.executable, __file__,
            "--worker-tx-dl", "--ue-ip", ue_ip,
            "--rate", str(offer_mbps), "--duration", str(duration),
            "--inner-tos", str(inner_tos),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=duration + 5)
    after = tc_classes(tc_if) if tc_if else {}
    stats = json.loads(out.strip())
    return stats["steady"]["mbps"], stats, tc_delta(before, after)


def run_parallel_ul_measure(
    qos_teid: int,
    qos_offer: float,
    nonqos_teid: int,
    nonqos_offer: float,
    duration: float = 4.0,
    tc_if: str | None = None,
    warm: float = 1.0,
    tail: float = 0.3,
) -> tuple[dict, dict]:
    before = tc_classes(tc_if) if tc_if else {}
    rx = subprocess.Popen(
        [
            "ip", "netns", "exec", DN_NS, sys.executable, __file__,
            "--worker-rx", "--duration", str(duration + 0.6),
            "--tx-dur", str(duration), "--warm", str(warm), "--tail", str(tail),
        ],
        stdout=subprocess.PIPE, text=True,
    )
    time.sleep(0.15)
    subprocess.run(
        cpu_pin(2) + [
            "ip", "netns", "exec", GNB_NS, sys.executable, __file__,
            "--worker-tx-parallel",
            "--teid", str(qos_teid), "--rate", str(qos_offer),
            "--teid2", str(nonqos_teid), "--rate2", str(nonqos_offer),
            "--duration", str(duration),
        ],
        check=True,
    )
    out, _ = rx.communicate(timeout=duration + 5)
    after = tc_classes(tc_if) if tc_if else {}
    return json.loads(out.strip()), tc_delta(before, after)


def close(val: float, exp: float, tol: float = 0.10, floor: float = 0.4) -> bool:
    return abs(val - exp) <= max(exp * tol, floor)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker-tx", action="store_true")
    p.add_argument("--worker-tx-parallel", action="store_true")
    p.add_argument("--worker-rx", action="store_true")
    p.add_argument("--worker-tx-dl", action="store_true")
    p.add_argument("--worker-rx-dl", action="store_true")
    p.add_argument("--teid", type=int, default=5555)
    p.add_argument("--teid2", type=int, default=7778)
    p.add_argument("--ue-ip", default=UE_DL_NONQOS)
    p.add_argument("--qfi", type=int, default=9)
    p.add_argument("--rate", type=float, default=15.0)
    p.add_argument("--rate2", type=float, default=20.0)
    p.add_argument("--duration", type=float, default=3.5)
    p.add_argument("--tx-dur", type=float, default=0.0)
    p.add_argument("--warm", type=float, default=0.8)
    p.add_argument("--tail", type=float, default=0.3)
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--inner-tos", type=int, default=0)
    p.add_argument("--sport", type=int, default=INNER_SPORT)
    p.add_argument("--mbr-ul", type=float, default=20.0, help="MBR UL configurato sulla UPF (Mbps)")
    p.add_argument("--gbr-ul", type=float, default=10.0, help="GBR UL configurato sulla UPF (Mbps)")
    p.add_argument("--non-qos-rate", type=float, default=10.0, help="--non-qos-rate della UPF (Mbps)")
    p.add_argument("--ef-rate", type=float, default=20.0, help="--ef-rate della UPF (Mbps)")
    p.add_argument("--tc-ul-if", default="veth-n6", help="Interfaccia egress UL (HTB)")
    p.add_argument("--tc-dl-if", default="veth-n3", help="Interfaccia egress DL (HTB)")
    args = p.parse_args()

    if args.worker_tx:
        worker_tx(args.teid, args.qfi, args.rate, args.duration, args.count, args.inner_tos, args.sport)
        return
    if args.worker_tx_parallel:
        worker_tx_parallel(args.teid, args.rate, args.teid2, args.rate2, args.duration)
        return
    if args.worker_rx:
        worker_rx(args.duration, args.tx_dur, args.warm, args.tail)
        return
    if args.worker_tx_dl:
        worker_tx_dl(args.ue_ip, args.rate, args.duration, args.count, args.inner_tos)
        return
    if args.worker_rx_dl:
        worker_rx_dl(args.duration, args.teid, args.tx_dur, args.warm, args.tail)
        return

    ok_all = True

    def check(label: str, cond: bool, detail: str = ""):
        nonlocal ok_all
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok_all = False
        print(f"[{status}] {label} {detail}")

    try:
        print("\n=== TEST 1: Robustezza errori (JSON, QFI, 5QI, burst, policy EF/GBR/Non-GBR) ===")
        r1 = send_cp('{"cmd":"add_uplink","teid":"non_valido"}')
        check("JSON malformato rifiutato", r1.get("ok") is False)

        r2 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6666, "far_id": 11,
            "qos": {"qer_id": 11, "qfi": 5, "gbr_mbps": 30, "mbr_mbps": 10},
        }))
        check("GBR > MBR rifiutato", r2.get("ok") is False)

        r2b = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6667, "far_id": 11,
            "qos": {"qer_id": 11, "qfi": 5, "gbr_mbps": 5, "mbr_mbps": 10, "burst_bytes": 500},
        }))
        check("MBR > 0 con burst_bytes < 1500 rifiutato", r2b.get("ok") is False)

        r2_qfi = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6668, "far_id": 11,
            "qos": {"five_qi": 2, "qer_id": 11, "qfi": 64, "gbr_mbps": 5, "mbr_mbps": 10},
        }))
        check("QFI > 63 rifiutato", r2_qfi.get("ok") is False)

        r2_5qi = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6669, "far_id": 11,
            "qos": {"five_qi": 99, "qer_id": 11, "qfi": 5, "gbr_mbps": 5, "mbr_mbps": 10},
        }))
        check("5QI sconosciuto (99) rifiutato", r2_5qi.get("ok") is False)

        r2_ef1 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6670, "far_id": 11,
            "qos": {"five_qi": 82, "qer_id": 11, "qfi": 10, "gbr_mbps": 5, "mbr_mbps": 10},
        }))
        check("5QI EF (82) con GBR != MBR rifiutato", r2_ef1.get("ok") is False)

        r2_ef0 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6671, "far_id": 11,
            "qos": {"five_qi": 82, "qer_id": 11, "qfi": 10, "gbr_mbps": 0, "mbr_mbps": 0},
        }))
        check("5QI EF (82) con rate 0/0 rifiutato", r2_ef0.get("ok") is False)

        r2_ngbr = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6672, "far_id": 11,
            "qos": {"five_qi": 5, "qer_id": 11, "qfi": 11, "gbr_mbps": 5, "mbr_mbps": 10},
        }))
        check("5QI Non-GBR (5) con GBR > 0 rifiutato", r2_ngbr.get("ok") is False)

        r2_gbr0 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 6673, "far_id": 11,
            "qos": {"five_qi": 2, "qer_id": 11, "qfi": 5, "gbr_mbps": 0, "mbr_mbps": 10},
        }))
        check("5QI GBR (2) con GBR=0 e MBR>0 rifiutato", r2_gbr0.get("ok") is False)

        print("\n=== TEST 2: Creazione sessione QoS live (TEID 5555, default 5QI=2 -> AF41 0x88) ===")
        before, _ = run_burst_probe(teid=5555, count=20)
        check("Prima di add_uplink: nessun pacchetto decapsulato", before["pkts"] == 0, f"(rx={before['pkts']})")

        r3 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 5555, "far_id": 10, "far_action": "forward",
            "qos": {"qer_id": 10, "qfi": 9, "gbr_mbps": 10, "mbr_mbps": 20, "burst_bytes": 15000},
        }))
        check("add_uplink TEID 5555 accettato", r3.get("ok") is True)

        after, dcls_5555 = run_burst_probe(teid=5555, count=20, tc_if=args.tc_ul_if)
        check(
            "Dopo add_uplink: 20/20 decapsulati, AF41 (0x88) e classe 1:21",
            after["pkts"] == 20
            and after["green"] == 20
            and after["bad_csum"] == 0
            and dcls_5555.get("1:21", 0) >= 20,
            f"(rx={after['pkts']}, af41={after['green']}, bad_csum={after['bad_csum']}, tc={dcls_5555})",
        )

        print("\n=== TEST 3: Cambio banda live (20 Mbps -> 2 Mbps -> declassamento Non-QoS 1:42) ===")
        mbps_hi, st_hi, _ = run_rate_measure(teid=5555, offer_mbps=15.0, duration=3.5)
        check(
            "Con MBR=20, flusso a 15 Mbps passa quasi intatto (AF41/AF43)",
            close(mbps_hi, 15.0) and st_hi["bad_csum"] == 0 and st_hi["green"] > 0 and st_hi["yellow"] > 0,
            f"(regime={mbps_hi:.2f} Mbps, af41={st_hi['green']}, af43={st_hi['yellow']})",
        )

        r4 = send_cp(json.dumps({
            "cmd": "update_qer", "qer_id": 10, "qfi": 9,
            "gbr_ul_mbps": 1, "mbr_ul_mbps": 2,
        }))
        check("update_qer a GBR=1 / MBR=2 (default 5QI=2) accettato", r4.get("ok") is True)

        mbps_lo, st_lo, _ = run_rate_measure(teid=5555, offer_mbps=15.0, duration=3.5)
        check(
            "Dopo update_qer, throughput tagliato a ~2 Mbps",
            1.6 <= mbps_lo <= 2.4 and st_lo["green"] > 0 and st_lo["yellow"] > 0,
            f"(regime={mbps_lo:.2f} Mbps, af41={st_lo['green']}, af43={st_lo['yellow']})",
        )

        r4_bad = send_cp(json.dumps({
            "cmd": "update_qer", "qer_id": 10, "qfi": 9,
            "gbr_ul_mbps": 1, "mbr_ul_mbps": 5, "burst_bytes": 500,
        }))
        check("update_qer con MBR>0 e burst<1500 rifiutato", r4_bad.get("ok") is False)

        r4_nq = send_cp(json.dumps({
            "cmd": "update_qer", "qer_id": 10, "qfi": 9,
            "gbr_ul_mbps": 0, "mbr_ul_mbps": 0,
        }))
        check("update_qer declassamento a Non-QoS (0/0 -> 5QI=9) accettato", r4_nq.get("ok") is True)

        mbps_nq, st_nq, dcls_nq = run_rate_measure(
            teid=5555, offer_mbps=2.0 * args.non_qos_rate, duration=3.5, tc_if=args.tc_ul_if
        )
        check(
            f"Dopo declassamento 0/0: TOS 0x00, classe 1:42 e rate ~{args.non_qos_rate:.0f} Mbps",
            close(mbps_nq, args.non_qos_rate)
            and st_nq["non_qos"] == st_nq["pkts"]
            and st_nq["green"] == 0
            and st_nq["yellow"] == 0
            and dcls_nq.get("1:42", 0) > 0
            and dcls_nq.get("1:21", 0) == 0
            and dcls_nq.get("1:22", 0) == 0
            and dcls_nq.get("1:10", 0) == 0,
            f"(regime={mbps_nq:.2f} Mbps, tos0={st_nq['non_qos']}/{st_nq['pkts']}, tc={dcls_nq})",
        )
        wait_tc_drain(args.tc_ul_if, "1:42")

        print("\n=== TEST 4: Rilascio sessione (delete_uplink TEID 5555) ===")
        r5 = send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5555}))
        check("delete_uplink TEID 5555 accettato", r5.get("ok") is True)

        after_del, _ = run_burst_probe(teid=5555, count=20)
        check("Dopo delete_uplink: nessun pacchetto decapsulato", after_del["pkts"] == 0, f"(rx={after_del['pkts']})")

        r6 = send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5555}))
        check("Seconda delete_uplink restituisce errore (PDR non trovata)", r6.get("ok") is False)

        print("\n=== TEST 5: Flusso Non-QoS UL (qos=null) + Anti-Spoofing TOS + Shaper 1:42 ===")
        r7 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 7777, "far_id": 12, "far_action": "forward", "qos": None,
        }))
        check("add_uplink Non-QoS (qos=null) TEID 7777 accettato", r7.get("ok") is True)

        sp, dcls_sp = run_burst_probe(teid=7777, count=20, inner_tos=TOS_EF, tc_if=args.tc_ul_if)
        check(
            "Anti-spoofing UL (inner EF 0xB8 -> 0x00, checksum ok, classe 1:42)",
            sp["pkts"] == 20
            and sp["non_qos"] == 20
            and sp["green"] == 0
            and sp["bad_csum"] == 0
            and dcls_sp.get("1:42", 0) >= 20
            and dcls_sp.get("1:10", 0) == 0
            and dcls_sp.get("1:21", 0) == 0
            and dcls_sp.get("1:41", 0) == 0,
            f"(rx={sp['pkts']}, tos0={sp['non_qos']}, bad_csum={sp['bad_csum']}, tc={dcls_sp})",
        )

        mbps_7777, st_7777, dcls_7777 = run_rate_measure(
            teid=7777, offer_mbps=2.0 * args.non_qos_rate, duration=3.5, inner_tos=TOS_AF41, tc_if=args.tc_ul_if
        )
        check(
            f"Shaper Non-QoS UL 1:42 livella a ~{args.non_qos_rate:.0f} Mbps con 100% TOS 0x00",
            close(mbps_7777, args.non_qos_rate)
            and st_7777["non_qos"] == st_7777["pkts"]
            and st_7777["bad_csum"] == 0
            and dcls_7777.get("1:42", 0) > 0
            and dcls_7777.get("1:10", 0) == 0
            and dcls_7777.get("1:21", 0) == 0
            and dcls_7777.get("1:22", 0) == 0,
            f"(regime={mbps_7777:.2f} Mbps, tos0={st_7777['non_qos']}/{st_7777['pkts']}, tc={dcls_7777})",
        )
        wait_tc_drain(args.tc_ul_if, "1:42")
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 7777}))

        print("\n=== TEST 6: Isolamento parallelo UL (QoS TEID 9999 -> 1:21/1:22 vs Non-QoS TEID 7778 -> 1:42) ===")
        r8 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 7778, "far_id": 13, "far_action": "forward",
            "qos": {"qer_id": 13, "qfi": 9, "gbr_mbps": 0, "mbr_mbps": 0},
        }))
        check("add_uplink Non-GBR (gbr=0, mbr=0, qfi=9, 5QI=9) TEID 7778 accettato", r8.get("ok") is True)
        time.sleep(1.5)

        par, dcls_par = run_parallel_ul_measure(
            qos_teid=9999,
            qos_offer=1.5 * args.mbr_ul,
            nonqos_teid=7778,
            nonqos_offer=2.0 * args.non_qos_rate,
            duration=4.0,
            tc_if=args.tc_ul_if,
        )
        empty = {
            "pkts": 0, "bytes": 0, "green": 0, "yellow": 0, "non_qos": 0, "bad_csum": 0,
            "steady": {"mbps": 0.0, "pkts": 0, "green": 0, "yellow": 0, "non_qos": 0, "tos_counts": {}},
        }
        b_qos = par["by_sport"].get("4001", empty)
        b_nq = par["by_sport"].get("4002", empty)
        mbps_qos = b_qos["steady"]["mbps"]
        mbps_nq2 = b_nq["steady"]["mbps"]
        s_qos = b_qos["steady"]
        g_share = s_qos["green"] / s_qos["pkts"] if s_qos["pkts"] else 0.0
        exp_g = args.gbr_ul / args.mbr_ul

        check(
            f"Parallelo - Flusso QoS (9999, 5QI=2) non degradato (~{args.mbr_ul:.0f} Mbps, AF41 ~{exp_g:.2f})",
            close(mbps_qos, args.mbr_ul)
            and abs(g_share - exp_g) <= 0.10
            and b_qos["non_qos"] == 0
            and b_qos["bad_csum"] == 0,
            f"(regime={mbps_qos:.2f} Mbps, verde={g_share:.2f}, af41={s_qos['green']}, af43={s_qos['yellow']})",
        )
        check(
            f"Parallelo - Flusso Non-QoS (7778, 5QI=9) isolato (~{args.non_qos_rate:.0f} Mbps, 100% TOS 0x00)",
            close(mbps_nq2, args.non_qos_rate)
            and b_nq["non_qos"] == b_nq["pkts"]
            and b_nq["pkts"] > 0
            and b_nq["bad_csum"] == 0
            and dcls_par.get("1:21", 0) > 0
            and dcls_par.get("1:22", 0) > 0
            and dcls_par.get("1:42", 0) > 0,
            f"(regime={mbps_nq2:.2f} Mbps, tos0={b_nq['non_qos']}/{b_nq['pkts']}, tc={dcls_par})",
        )
        wait_tc_drain(args.tc_ul_if, "1:42")
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 7778}))
        time.sleep(0.5)

        print("\n=== TEST 7: Flusso Non-QoS Downlink (QFI 7, 5QI=9, outer TOS 0x00, classe 1:42) ===")
        r9 = send_cp(json.dumps({
            "cmd": "add_downlink", "ue_ip": UE_DL_NONQOS, "far_id": 14, "far_action": "forward",
            "peer_ip": GNB_N3_IP, "peer_teid": 7002, "local_ip": UPF_N3_IP,
            "qos": {"qer_id": 14, "qfi": 7, "gbr_mbps": 0, "mbr_mbps": 0},
        }))
        check("add_downlink Non-GBR (QFI 7, 0/0) accettato", r9.get("ok") is True)

        dl_sp, dcls_dl_sp = run_dl_probe(
            ue_ip=UE_DL_NONQOS, target_teid=7002, count=20, inner_tos=TOS_AF41, tc_if=args.tc_dl_if
        )
        check(
            "DL Non-QoS probe: 20/20 encap, QFI=7, outer TOS=0x00 (anti-spoofing), classe 1:42",
            dl_sp["pkts"] == 20
            and dl_sp["non_qos"] == 20
            and dl_sp["green"] == 0
            and dl_sp["bad_outer_csum"] == 0
            and dl_sp["qfis"].get("7", 0) == 20
            and dcls_dl_sp.get("1:42", 0) >= 20
            and dcls_dl_sp.get("1:21", 0) == 0
            and dcls_dl_sp.get("1:10", 0) == 0,
            f"(rx={dl_sp['pkts']}, tos0={dl_sp['non_qos']}, qfis={dl_sp['qfis']}, tc={dcls_dl_sp})",
        )

        mbps_dl, st_dl, dcls_dl = run_dl_rate_measure(
            ue_ip=UE_DL_NONQOS, target_teid=7002,
            offer_mbps=2.0 * args.non_qos_rate, duration=3.5, inner_tos=TOS_AF41, tc_if=args.tc_dl_if
        )
        check(
            f"Shaper Non-QoS DL 1:42 livella a ~{args.non_qos_rate:.0f} Mbps con 100% outer TOS 0x00",
            close(mbps_dl, args.non_qos_rate)
            and st_dl["non_qos"] == st_dl["pkts"]
            and st_dl["bad_outer_csum"] == 0
            and dcls_dl.get("1:42", 0) > 0
            and dcls_dl.get("1:21", 0) == 0
            and dcls_dl.get("1:10", 0) == 0,
            f"(regime={mbps_dl:.2f} Mbps, tos0={st_dl['non_qos']}/{st_dl['pkts']}, tc={dcls_dl})",
        )
        wait_tc_drain(args.tc_dl_if, "1:42")

        r10 = send_cp(json.dumps({"cmd": "delete_downlink", "ue_ip": UE_DL_NONQOS}))
        check("delete_downlink UE 10.60.0.2 accettato", r10.get("ok") is True)
        dl_after, _ = run_dl_probe(ue_ip=UE_DL_NONQOS, target_teid=7002, count=10)
        check("Dopo delete_downlink: nessun pacchetto incapsulato", dl_after["pkts"] == 0, f"(rx={dl_after['pkts']})")

        print("\n=== TEST 8: Mappatura multi-classe 5QI -> DSCP / TC (EF, CS5, AF3x, AF11) ===")
        # 8a. 5QI = 82 (URLLC -> EF 0xB8, strict policing GBR == MBR, classe 1:10)
        ef_rate_test = max(2, int(min(10, args.ef_rate)))
        r8_ef = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 5582, "far_id": 21, "far_action": "forward",
            "qos": {"five_qi": 82, "qer_id": 21, "qfi": 10,
                    "gbr_mbps": ef_rate_test, "mbr_mbps": ef_rate_test, "burst_bytes": 15000},
        }))
        check("5QI=82 (URLLC / EF, QFI=10) accettato", r8_ef.get("ok") is True)

        mbps_ef, st_ef, dcls_ef = run_rate_measure(
            teid=5582, offer_mbps=1.8 * ef_rate_test, duration=3.5, tc_if=args.tc_ul_if, qfi=10
        )
        ef_cnt = st_ef["tos_counts"].get("0xb8", 0)
        check(
            f"5QI=82 strict policing (~{ef_rate_test} Mbps, 100% EF 0xB8, classe 1:10)",
            close(mbps_ef, ef_rate_test)
            and ef_cnt == st_ef["pkts"]
            and st_ef["pkts"] > 0
            and st_ef["bad_csum"] == 0
            and dcls_ef.get("1:10", 0) > 0
            and dcls_ef.get("1:21", 0) == 0,
            f"(regime={mbps_ef:.2f} Mbps, ef={ef_cnt}/{st_ef['pkts']}, tc={dcls_ef})",
        )
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5582}))

        # 8b. 5QI = 5 (IMS Signalling Non-GBR -> CS5 0xA0, classe 1:10)
        r8_cs5 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 5505, "far_id": 22, "far_action": "forward",
            "qos": {"five_qi": 5, "qer_id": 22, "qfi": 11, "gbr_mbps": 0, "mbr_mbps": 0},
        }))
        check("5QI=5 (IMS Signalling / CS5, QFI=11) accettato", r8_cs5.get("ok") is True)

        st_cs5, dcls_cs5 = run_burst_probe(teid=5505, count=20, inner_tos=0x00, tc_if=args.tc_ul_if, qfi=11)
        cs5_cnt = st_cs5["tos_counts"].get("0xa0", 0)
        check(
            "5QI=5 Non-GBR: 20/20 marcati CS5 (0xA0) e instradati in 1:10",
            st_cs5["pkts"] == 20
            and cs5_cnt == 20
            and st_cs5["bad_csum"] == 0
            and dcls_cs5.get("1:10", 0) >= 20,
            f"(rx={st_cs5['pkts']}, cs5={cs5_cnt}, bad_csum={st_cs5['bad_csum']}, tc={dcls_cs5})",
        )
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5505}))

        # 8c. 5QI = 4 (Buffered Video GBR -> AF31 0x68 / AF33 0x78, classi 1:31 / 1:32)
        r8_af3 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 5504, "far_id": 23, "far_action": "forward",
            "qos": {"five_qi": 4, "qer_id": 23, "qfi": 12,
                    "gbr_mbps": int(args.gbr_ul), "mbr_mbps": int(args.mbr_ul), "burst_bytes": 15000},
        }))
        check("5QI=4 (Buffered Video / AF3x, QFI=12) accettato", r8_af3.get("ok") is True)

        mbps_af3, st_af3, dcls_af3 = run_rate_measure(
            teid=5504, offer_mbps=1.5 * args.mbr_ul, duration=3.5, tc_if=args.tc_ul_if, qfi=12
        )
        st_tc = st_af3["steady"]["tos_counts"]
        af31_s = st_tc.get("0x68", 0)
        af33_s = st_tc.get("0x78", 0)
        af3_tot = st_af3["steady"]["pkts"]
        af3_share = af31_s / af3_tot if af3_tot else 0.0
        exp_af3_g = args.gbr_ul / args.mbr_ul
        check(
            f"5QI=4 trTCM (~{args.mbr_ul:.0f} Mbps, AF31 ~{exp_af3_g:.2f}, classi 1:31/1:32)",
            close(mbps_af3, args.mbr_ul)
            and abs(af3_share - exp_af3_g) <= 0.10
            and af33_s > 0
            and st_af3["bad_csum"] == 0
            and dcls_af3.get("1:31", 0) > 0
            and dcls_af3.get("1:32", 0) > 0
            and dcls_af3.get("1:21", 0) == 0,
            f"(regime={mbps_af3:.2f} Mbps, af31={af31_s}, af33={af33_s}, share={af3_share:.2f}, tc={dcls_af3})",
        )
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5504}))

        # 8d. 5QI = 6 (Interactive Non-GBR -> AF11 0x28, classe 1:41, anti-spoofing da 0xB8)
        r8_af11 = send_cp(json.dumps({
            "cmd": "add_uplink", "teid": 5506, "far_id": 24, "far_action": "forward",
            "qos": {"five_qi": 6, "qer_id": 24, "qfi": 13, "gbr_mbps": 0, "mbr_mbps": 0},
        }))
        check("5QI=6 (Interactive Non-GBR / AF11, QFI=13) accettato", r8_af11.get("ok") is True)

        st_af11, dcls_af11 = run_burst_probe(teid=5506, count=20, inner_tos=TOS_EF, tc_if=args.tc_ul_if, qfi=13)
        af11_cnt = st_af11["tos_counts"].get("0x28", 0)
        check(
            "5QI=6 Non-GBR: 20/20 riscritti da 0xB8 ad AF11 (0x28) in classe 1:41",
            st_af11["pkts"] == 20
            and af11_cnt == 20
            and st_af11["bad_csum"] == 0
            and dcls_af11.get("1:41", 0) >= 20
            and dcls_af11.get("1:10", 0) == 0,
            f"(rx={st_af11['pkts']}, af11={af11_cnt}, bad_csum={st_af11['bad_csum']}, tc={dcls_af11})",
        )
        send_cp(json.dumps({"cmd": "delete_uplink", "teid": 5506}))

    finally:
        for cmd in (
            {"cmd": "delete_uplink", "teid": 5555},
            {"cmd": "delete_uplink", "teid": 7777},
            {"cmd": "delete_uplink", "teid": 7778},
            {"cmd": "delete_uplink", "teid": 5582},
            {"cmd": "delete_uplink", "teid": 5505},
            {"cmd": "delete_uplink", "teid": 5504},
            {"cmd": "delete_uplink", "teid": 5506},
            {"cmd": "delete_downlink", "ue_ip": UE_DL_NONQOS},
        ):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                sock.sendto(json.dumps(cmd).encode(), CP_ADDR)
                sock.recvfrom(1024)
                sock.close()
            except Exception:
                pass

    print("\n" + ("=== TUTTI I TEST SUPERATI ===" if ok_all else "=== ALCUNI TEST FALLITI ==="))
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()