"""
Self-test UPLINK dell'UPF: parsing GTP-U, decap, QoS (trTCM/GCRA),
shaper TC multi-classe 3GPP/RFC 4594/GSMA IR.34 (QoS 1:21/1:22 vs Non-QoS 1:42),
anti-spoofing DSCP e isolamento.

Va eseguito DENTRO ns-gnb:
    sudo taskset -c 2 ip netns exec ns-gnb python3 scripts/upf_ul_selftest.py \
        --mbr 20 --gbr 10 --non-qos-rate 10 --tc-if veth-n6 \
        --green-class 1:21 --yellow-class 1:22 --non-qos-class 1:42 \
        --burst-bytes 15000 --htb-overhead 0

Fasi:
  1. FUNZ    parsing/decap + policy (DROP / no PDR) + marcatura AF41 (0x88)
  2. RATE    sweep del rate offerto (trTCM + TC 1:21/1:22)
  3. SIZE    invarianza rispetto alla dimensione del pacchetto
  4. BURST   raffica back-to-back dopo quiete
  5. RECOV   ricarica del bucket dopo pausa
  6. NONQOS  flussi Non-QoS (qos=null e Non-GBR 0/0), anti-spoofing TOS (0x88/0x98/0xB8 -> 0x00)
             e shaping dedicato sulla classe 1:42 (rate a regime su finestra temporale)
  7. ISO     isolamento parallelo QoS (TEID 9999 -> 1:21/1:22) vs Non-QoS (TEID 7771 -> 1:42)
"""

import argparse
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

from scapy.all import Ether, IP, UDP, Raw, PcapReader

from netns_topology import (
    IFACE_GNB, MAC_GNB, MAC_N3, IP_GNB, IP_N3, IP_DN,
    UE_IP, TEID_UL, TEID_UL_DROP, GTP_PORT,
)

DN_PORT = 5000
NS_DN = "ns-dn"
IFACE_DN = "veth-dn"
TEID_NO_PDR = 55555          # TEID che NON ha PDR installato
TEID_NONQOS_NULL = 7771      # TEID temporaneo creato via CP con qos=null
TEID_NONQOS_ZERO = 7772      # TEID temporaneo creato via CP con gbr=0, mbr=0, qfi=9

TOS_EF = 0xB8                # 5QI 82..85 (Real-Time EF)    -> 1:10
TOS_GREEN = 0x88             # 5QI 2 Verde (AF41)           -> 1:21
TOS_YELLOW = 0x98            # 5QI 2 Giallo (AF43)          -> 1:22
TOS_NONQOS = 0x00            # 5QI 9 / qos=null (CS0 BE)    -> 1:42

EXT_PDU_SESSION = 0x85
EXT_UDP_PORT = 0x40
L2_OVERHEAD = 14             # in UL l'HTB vede IP interno + header Ethernet


def shaped_limit(rate_mbps, ip_len):
    """Rate (Mbps di IP interno) massimo in uscita dall'HTB."""
    return rate_mbps * ip_len / (ip_len + L2_OVERHEAD)


# ---------------------------------------------------------------- costruzione

def gtp_u(flags, body=b"", teid=TEID_UL, msg_type=255):
    return struct.pack("!BBHI", flags, msg_type, len(body), teid) + body


def opt(next_type=0, seq=1, npdu=0):
    return struct.pack("!HBB", seq, npdu, next_type)


def ext_pdu_session(qfi, next_type=0, pdu_type=0):
    return struct.pack("!BBBB", 1, pdu_type << 4, qfi & 0x3F, next_type)


def ext_riempitivo(next_type):
    return struct.pack("!BHB", 1, GTP_PORT, next_type)


def inner_packet(sport, ip_len=None, text=b"ping-dn", tos=0):
    """IP interno UE -> DN. Se ip_len e' dato, il payload UDP viene
    riempito in modo che la lunghezza totale IP sia esattamente ip_len."""
    if ip_len is not None:
        pad = max(0, ip_len - 28)
        text = (b"x" * pad)[:pad]
    return bytes(IP(src=UE_IP, dst=IP_DN, tos=tos) / UDP(sport=sport, dport=DN_PORT) / Raw(text))


def frame(gtp_payload):
    return bytes(Ether(src=MAC_GNB, dst=MAC_N3) / IP(src=IP_GNB, dst=IP_N3)
                 / UDP(sport=50000, dport=GTP_PORT) / Raw(gtp_payload))


def ul_frame(sport, ip_len=None, teid=TEID_UL, qfi=5, tos=0):
    """Caso 'standard' per i test di rate: E flag + PDU Session Container."""
    body = opt(EXT_PDU_SESSION) + ext_pdu_session(qfi) + inner_packet(sport, ip_len, tos=tos)
    return frame(gtp_u(0x34, body, teid=teid))


# ------------------------------------------------------------------ invio

_sock = None


def sock():
    global _sock
    if _sock is None:
        _sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        _sock.bind((IFACE_GNB, 0))
    return _sock


def send_paced(fr, pps, dur):
    """Invia `fr` a `pps` per `dur` secondi (pacing uniforme, recupera i ritardi)."""
    s = sock()
    t0 = time.perf_counter()
    end = t0 + dur
    n = 0
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        due = int((now - t0) * pps) + 1
        while n < due:
            s.send(fr)
            n += 1
        time.sleep(0.0002)
    return n


def send_paced_multi(flows, dur):
    """Invia piu' flussi interleaved sullo stesso socket/CPU.
    flows: lista di tuple (frame_bytes, pps). Ritorna i conteggi inviati."""
    s = sock()
    t0 = time.perf_counter()
    end = t0 + dur
    sent = [0] * len(flows)
    while True:
        now = time.perf_counter()
        if now >= end:
            break
        elapsed = now - t0
        progressed = False
        for i, (fr, pps) in enumerate(flows):
            due = int(elapsed * pps) + 1
            if sent[i] < due:
                s.send(fr)
                sent[i] += 1
                progressed = True
        if not progressed:
            time.sleep(0.0002)
    return sent


def send_burst(fr, count):
    s = sock()
    t0 = time.perf_counter()
    for _ in range(count):
        s.send(fr)
    return count, time.perf_counter() - t0


# ---------------------------------------------------------------- cattura

LAST_CAP = None
LAST_OFFERED = 0.0


def _cap_affinity():
    """tcpdump eredita l'affinita' del sender (taskset): lo spostiamo su altre CPU."""
    mine = os.sched_getaffinity(0)
    others = set(range(os.cpu_count())) - mine
    if others:
        os.sched_setaffinity(0, others)


def start_cap(name):
    path = f"/tmp/ul_{name}.pcap"
    log = f"/tmp/ul_{name}.log"
    for f in (path, log):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    p = subprocess.Popen(
        ["ip", "netns", "exec", NS_DN, "tcpdump", "-Z", "root", "-i", IFACE_DN,
         "-n", "-U", "-B", "16384", "-w", path, "udp", "dst", "port", str(DN_PORT)],
        stdout=subprocess.DEVNULL, stderr=open(log, "w"), preexec_fn=_cap_affinity)
    time.sleep(1.0)
    if p.poll() is not None:
        sys.exit(f"tcpdump non e' partito, vedi {log}:\n{open(log).read()}")
    p.log = log
    return p, path


def stop_cap(p):
    global LAST_CAP
    time.sleep(0.7)
    p.send_signal(signal.SIGINT)
    p.wait()
    try:
        txt = open(p.log).read()
        m = re.search(r"(\d+) packets captured", txt)
        d = re.search(r"(\d+) packets dropped by kernel", txt)
        LAST_CAP = (int(m.group(1)) if m else None, int(d.group(1)) if d else 0)
    except Exception:
        LAST_CAP = None


def ip_csum_ok(hdr):
    s = 0
    for i in range(0, len(hdr) - 1, 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def read_cap(path):
    """Ritorna lista di dict: t, ip_len, sport, tos, ip_ok, key."""
    out = []
    for pkt in PcapReader(path):
        raw = bytes(pkt)
        if len(raw) < 14 + 20 or raw[12:14] != b"\x08\x00":
            continue
        ip = raw[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        sport, dport, _ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
        payload = ip[ihl + 8:total]
        out.append(dict(
            t=float(pkt.time), ip_len=total, sport=sport, tos=ip[1],
            ip_ok=ip_csum_ok(ip[:ihl]),
            key=(ip[12:16], ip[16:20], total, sport, dport, payload),
        ))
    return out


# ----------------------------------------------------------- tc & control plane

def upf_prefix(args):
    if args.upf_ns == "host":
        return ["nsenter", "-t", "1", "-n"]
    return ["ip", "netns", "exec", args.upf_ns]


def send_cp(args, payload_dict):
    """Invia un comando JSON al Control Plane UDP della UPF (nel suo namespace)."""
    host, port_s = args.cp_addr.rsplit(":", 1)
    code = (
        "import socket, sys; "
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        "s.settimeout(2.0); "
        "s.sendto(sys.argv[1].encode(), (sys.argv[2], int(sys.argv[3]))); "
        "print(s.recvfrom(4096)[0].decode(), end='')"
    )
    res = subprocess.run(
        upf_prefix(args) + [sys.executable, "-c", code, json.dumps(payload_dict), host, port_s],
        capture_output=True, text=True, timeout=5,
    )
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(f"CP command failed: {res.stderr.strip()}")
    return json.loads(res.stdout.strip())


def tc_state(args):
    """Ritorna ({classid: sent_pkts}, {classid: backlog_pkts}) da `tc -s class show`."""
    try:
        txt = subprocess.run(upf_prefix(args) + ["tc", "-s", "class", "show", "dev", args.tc_if],
                             capture_output=True, text=True, timeout=5).stdout
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


def tc_classes(args):
    return tc_state(args)[0]


def tc_delta(before, after):
    return {c: after.get(c, 0) - before.get(c, 0) for c in after}


def wait_tc_drain(args, classid=None, timeout=15.0):
    """Attende che il backlog della classe Non-QoS (fq_codel 42:) si svuoti completamente."""
    cid = classid or args.non_qos_class or "1:42"
    t0 = time.monotonic()
    prev = tc_state(args)[0].get(cid, 0)
    stable = 0
    while time.monotonic() - t0 < timeout:
        time.sleep(0.25)
        sent, backlog = tc_state(args)
        cur = sent.get(cid, 0)
        bl = backlog.get(cid, 0)
        if bl == 0 and cur == prev:
            stable += 1
            if stable >= 2:
                break
        else:
            stable = 0
            prev = cur
    elapsed = time.monotonic() - t0
    if elapsed > 0.8:
        print(f"  (drain coda TC {args.tc_if} [{cid}] completato in {elapsed:.1f}s)")
    time.sleep(0.2)


# -------------------------------------------------------------- misure

def steady_rate_mbps(pkts, dur, warm=1.0, tail=0.3):
    return sum(p["ip_len"] for p in pkts) * 8 / dur / 1e6


def windowed_rate_mbps(pkts, dur, warm=1.0, tail=0.3):
    """Rate (Mbps di IP interno) a regime nella finestra [t0 + warm, t0 + dur - tail],
    immune sia al burst iniziale sia allo svuotamento post-invio di fq_codel."""
    if not pkts:
        return 0.0
    t0 = pkts[0]["t"]
    a, b = t0 + warm, t0 + dur - tail
    if b <= a + 0.1:
        return steady_rate_mbps(pkts, dur)
    sel = [p for p in pkts if a <= p["t"] <= b]
    if not sel:
        return 0.0
    return sum(p["ip_len"] for p in sel) * 8 / (b - a) / 1e6


def green_share(pkts, dur, warm=1.0, tail=0.3):
    """Quota di pacchetti verdi (AF41 = TOS 0x88) a regime, letta dal TOS dell'IP uscente."""
    if not pkts:
        return None
    t0 = pkts[0]["t"]
    sel = [p for p in pkts if t0 + warm <= p["t"] <= t0 + dur - tail]
    if not sel:
        return None
    return sum(1 for p in sel if (p["tos"] & 0xFC) == TOS_GREEN) / len(sel)


RESULTS = []


def report(name, ok, detail):
    tag = "PASS" if ok is True else ("FAIL" if ok is False else "INFO")
    RESULTS.append((tag, name, detail))
    print(f"  [{tag}] {name}: {detail}")


def close(val, exp, tol=0.08, floor=0.3):
    return abs(val - exp) <= max(exp * tol, floor)


# ------------------------------------------------------------------ fasi

def phase_func():
    print("\n=== FASE 1: parsing / decap / policy (basso rate, 5QI=2 -> AF41 0x88) ===")
    N = 20
    casi = [
        ("0x30 nessun ext header", 4001,
         frame(gtp_u(0x30, inner_packet(4001))), True),
        ("0x32 solo seq (S)", 4002,
         frame(gtp_u(0x32, opt(0) + inner_packet(4002))), True),
        ("0x34 + PDU Session Container (QFI 5)", 4003,
         frame(gtp_u(0x34, opt(EXT_PDU_SESSION) + ext_pdu_session(5) + inner_packet(4003))), True),
        ("0x34 catena di 2 extension header (QFI 9)", 4004,
         frame(gtp_u(0x34, opt(EXT_UDP_PORT) + ext_riempitivo(EXT_PDU_SESSION)
                     + ext_pdu_session(9) + inner_packet(4004))), True),
        ("TEID in DROP", 4005,
         frame(gtp_u(0x30, inner_packet(4005), teid=TEID_UL_DROP)), False),
        ("TEID senza PDR", 4006,
         frame(gtp_u(0x30, inner_packet(4006), teid=TEID_NO_PDR)), False),
    ]
    expected_keys = {
        4001: inner_packet(4001), 4002: inner_packet(4002),
        4003: inner_packet(4003), 4004: inner_packet(4004),
    }
    p, path = start_cap("func")
    for _, _, fr, _ in casi:
        send_paced(fr, 100, N / 100)
        time.sleep(0.2)
    stop_cap(p)
    pkts = read_cap(path)
    for nome, sport, fr, fwd in casi:
        got = [x for x in pkts if x["sport"] == sport]
        if fwd:
            ref = expected_keys[sport]
            ref_ip = IP(ref)
            ref_pl = bytes(ref_ip[UDP].payload)
            good = [x for x in got
                    if x["ip_ok"] and (x["tos"] & 0xFC) == TOS_GREEN
                    and x["key"][2] == len(ref) and x["key"][5] == ref_pl
                    and x["key"][0] == socket.inet_aton(ref_ip.src)
                    and x["key"][1] == socket.inet_aton(ref_ip.dst)]
            report(nome, len(good) == N and len(got) == N,
                   f"usciti {len(got)}/{N}, contenuto/checksum/AF41(0x88) corretto {len(good)}/{N}")
        else:
            report(nome, len(got) == 0, f"usciti {len(got)} (atteso 0)")


def run_rate(args, offered_mbps, ip_len, dur, tag):
    global LAST_OFFERED
    pps = offered_mbps * 1e6 / 8 / ip_len
    fr = ul_frame(4100 + ip_len % 100, ip_len)
    before = tc_classes(args)
    p, path = start_cap(tag)
    n_sent = send_paced(fr, pps, dur)
    LAST_OFFERED = n_sent * ip_len * 8 / dur / 1e6
    stop_cap(p)
    after = tc_classes(args)
    pkts = read_cap(path)
    return steady_rate_mbps(pkts, dur), tc_delta(before, after), len(pkts), green_share(pkts, dur)


def phase_rate(args):
    print("\n=== FASE 2: sweep del rate offerto (trTCM + TC 1:21/1:22) ===")
    mbr, gbr = args.mbr, args.gbr
    sweep = [0.5 * gbr, 0.9 * gbr, 0.5 * (gbr + mbr), 0.9 * mbr, 1.5 * mbr, 3 * mbr]
    for off in sweep:
        out, dcls, n, share_tos = run_rate(args, off, args.inner_len, args.dur, f"rate_{int(off)}")
        exp = min(off, mbr, shaped_limit(mbr, args.inner_len))
        ok = close(out, exp)
        extra = ""
        if share_tos is not None:
            exp_share_t = min(off, gbr) / exp
            okt = abs(share_tos - exp_share_t) <= 0.10
            extra += f"  verde(TOS 0x88)={share_tos:.2f} (atteso {exp_share_t:.2f}) {'ok' if okt else 'FUORI'}"
            ok = ok and okt
        if dcls:
            extra += "  classi(pkt)=" + ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v)
        if args.green_class and args.yellow_class and dcls:
            g, y = dcls.get(args.green_class, 0), dcls.get(args.yellow_class, 0)
            if g + y > 0:
                share = g / (g + y)
                exp_share = min(off, gbr) / exp
                okq = abs(share - exp_share) <= 0.10
                extra += f"  verde={share:.2f} (atteso {exp_share:.2f}) {'ok' if okq else 'FUORI'}"
                ok = ok and okq
        report(f"offerto {off:6.1f} Mbps", ok,
               f"uscita {out:6.2f} Mbps, atteso {exp:6.2f}{extra}  [offerto eff. {LAST_OFFERED:.1f} Mbps, tcpdump: {LAST_CAP}]")
        time.sleep(2.0)


def phase_size(args):
    print("\n=== FASE 3: invarianza rispetto alla dimensione del pacchetto ===")
    off = 1.5 * args.mbr
    for size in (100, 500, 1000, 1400):
        out, _, _, _ = run_rate(args, off, size, 4, f"size_{size}")
        lim = shaped_limit(args.mbr, size)
        ok = close(out, lim)
        if not ok and LAST_OFFERED < 1.1 * lim:
            report(f"IP interno {size:4d} B", None,
                   f"generatore limitato: offerto effettivo {LAST_OFFERED:.1f} Mbps "
                   f"(< 1.1 x MBR), uscita {out:6.2f} Mbps")
        else:
            report(f"IP interno {size:4d} B", ok,
                   f"uscita {out:6.2f} Mbps (offerto eff. {LAST_OFFERED:.1f}), "
                   f"atteso {lim:6.2f}  [tcpdump: {LAST_CAP}]")
        time.sleep(2.0)


def phase_burst(args):
    print("\n=== FASE 4: burst dopo quiete ===")
    time.sleep(3.0)
    n = 400
    fr = ul_frame(4200, 1000)
    p, path = start_cap("burst")
    _, el = send_burst(fr, n)
    stop_cap(p)
    pkts = read_cap(path)
    byt = sum(x["ip_len"] for x in pkts)
    msg = f"inviati {n} pacchetti da 1000 B back-to-back in {el * 1000:.1f} ms, usciti {len(pkts)} ({byt} B di IP interno)"
    if args.burst_bytes:
        exp = args.burst_bytes + args.mbr * 1e6 / 8 * el
        tol = max(2000, 0.05 * exp)
        report("burst tolerance", abs(byt - exp) <= tol,
               msg + f", atteso ~{exp:.0f} B (burst {args.burst_bytes} + ricarica durante l'invio)")
    else:
        report("burst tolerance", None, msg + " (passa --burst-bytes per un verdetto)")


def phase_recov(args):
    print("\n=== FASE 5: ricarica del bucket dopo pausa ===")
    send_burst(ul_frame(4300, 1000), 400)
    time.sleep(3.0)
    p, path = start_cap("recov")
    send_burst(ul_frame(4301, 200), 1)
    stop_cap(p)
    pkts = [x for x in read_cap(path) if x["sport"] == 4301]
    report("pacchetto dopo pausa", len(pkts) == 1, f"usciti {len(pkts)}/1")


def phase_nonqos(args):
    print(f"\n=== FASE 6: Non-QoS (qos=null e 0/0) + Anti-Spoofing TOS + Shaper {args.non_qos_class} ===")
    try:
        r1 = send_cp(args, {
            "cmd": "add_uplink", "teid": TEID_NONQOS_NULL, "far_id": 101,
            "far_action": "forward", "qos": None,
        })
        r2 = send_cp(args, {
            "cmd": "add_uplink", "teid": TEID_NONQOS_ZERO, "far_id": 102,
            "far_action": "forward",
            "qos": {"qer_id": 102, "qfi": 9, "gbr_mbps": 0, "mbr_mbps": 0},
        })
        if not (r1.get("ok") and r2.get("ok")):
            report("setup CP Non-QoS", False, f"r1={r1}, r2={r2}")
            return

        # 6a. Anti-spoofing: pacchetti Non-QoS pre-marcati 0x88 (AF41), 0x98 (AF43) e 0xB8 (EF)
        N = 20
        casi_spoof = [
            ("Non-QoS qos=null spoof AF41 0x88 -> 0x00", 4401, TEID_NONQOS_NULL, TOS_GREEN),
            ("Non-QoS qos=null spoof AF43 0x98 -> 0x00", 4402, TEID_NONQOS_NULL, TOS_YELLOW),
            ("Non-QoS Non-GBR (0/0) spoof EF 0xB8 -> 0x00", 4403, TEID_NONQOS_ZERO, TOS_EF),
        ]
        before = tc_classes(args)
        p, path = start_cap("nonqos_spoof")
        for _, sport, teid, st in casi_spoof:
            send_paced(ul_frame(sport, 500, teid=teid, qfi=9, tos=st), 100, N / 100)
            time.sleep(0.2)
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = read_cap(path)

        for nome, sport, _, _ in casi_spoof:
            got = [x for x in pkts if x["sport"] == sport]
            clean = [x for x in got if (x["tos"] & 0xFC) == TOS_NONQOS and x["ip_ok"]]
            report(
                nome,
                len(got) == N and len(clean) == N,
                f"usciti {len(got)}/{N}, ripuliti a TOS 0x00 con checksum ok {len(clean)}/{N}",
            )

        if args.non_qos_class and dcls:
            nq_pkts = dcls.get(args.non_qos_class, 0)
            g_pkts = dcls.get(args.green_class, 0) if args.green_class else 0
            y_pkts = dcls.get(args.yellow_class, 0) if args.yellow_class else 0
            ef_pkts = dcls.get("1:10", 0)
            af11_pkts = dcls.get("1:41", 0)
            report(
                f"anti-spoofing TC routing ({args.non_qos_class})",
                nq_pkts >= 3 * N and g_pkts == 0 and y_pkts == 0 and ef_pkts == 0 and af11_pkts == 0,
                f"classi(pkt)=" + ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v),
            )

        # 6b. Saturazione shaper Non-QoS (offerto = 2 * non_qos_rate, misura a regime su finestra)
        time.sleep(1.0)
        off = 2.0 * args.non_qos_rate
        pps = off * 1e6 / 8 / args.inner_len
        fr = ul_frame(4410, args.inner_len, teid=TEID_NONQOS_NULL, qfi=9, tos=TOS_GREEN)
        before = tc_classes(args)
        p, path = start_cap("nonqos_rate")
        n_sent = send_paced(fr, pps, args.dur)
        off_eff = n_sent * args.inner_len * 8 / args.dur / 1e6
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = [x for x in read_cap(path) if x["sport"] == 4410]

        out = windowed_rate_mbps(pkts, args.dur)
        exp = min(off, args.non_qos_rate, shaped_limit(args.non_qos_rate, args.inner_len))
        all_tos0 = bool(pkts) and all((x["tos"] & 0xFC) == TOS_NONQOS and x["ip_ok"] for x in pkts)
        tc_ok = True
        if args.non_qos_class and dcls:
            tc_ok = (
                dcls.get(args.non_qos_class, 0) > 0
                and dcls.get("1:10", 0) == 0
                and dcls.get("1:41", 0) == 0
                and (not args.green_class or dcls.get(args.green_class, 0) == 0)
                and (not args.yellow_class or dcls.get(args.yellow_class, 0) == 0)
            )
        report(
            f"Non-QoS saturazione {off:.1f} Mbps -> shaper {args.non_qos_class}",
            close(out, exp, tol=0.08) and all_tos0 and tc_ok,
            f"regime {out:.2f} Mbps (atteso {exp:.2f}), 100% TOS 0x00/csum={'ok' if all_tos0 else 'FAIL'}, "
            f"classi(pkt)=" + ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v)
            + f"  [offerto eff. {off_eff:.1f} Mbps, tcpdump: {LAST_CAP}]",
        )
        wait_tc_drain(args)
    finally:
        for teid in (TEID_NONQOS_NULL, TEID_NONQOS_ZERO):
            try:
                send_cp(args, {"cmd": "delete_uplink", "teid": teid})
            except Exception:
                pass


def phase_iso(args):
    print(f"\n=== FASE 7: Isolamento parallelo QoS ({args.green_class}/{args.yellow_class}) vs Non-QoS ({args.non_qos_class}) ===")
    try:
        r = send_cp(args, {
            "cmd": "add_uplink", "teid": TEID_NONQOS_NULL, "far_id": 101,
            "far_action": "forward", "qos": None,
        })
        if not r.get("ok"):
            report("setup CP isolamento", False, f"resp={r}")
            return

        wait_tc_drain(args)
        time.sleep(1.5)
        off_qos = 1.5 * args.mbr
        off_nq = 2.0 * args.non_qos_rate
        pps_qos = off_qos * 1e6 / 8 / args.inner_len
        pps_nq = off_nq * 1e6 / 8 / args.inner_len

        fr_qos = ul_frame(4501, args.inner_len, teid=TEID_UL, qfi=5, tos=0x00)
        fr_nq = ul_frame(4502, args.inner_len, teid=TEID_NONQOS_NULL, qfi=9, tos=TOS_GREEN)

        before = tc_classes(args)
        p, path = start_cap("iso")
        sent = send_paced_multi([(fr_qos, pps_qos), (fr_nq, pps_nq)], args.dur)
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = read_cap(path)

        pkts_qos = [x for x in pkts if x["sport"] == 4501]
        pkts_nq = [x for x in pkts if x["sport"] == 4502]

        out_qos = windowed_rate_mbps(pkts_qos, args.dur)
        out_nq = windowed_rate_mbps(pkts_nq, args.dur)
        exp_qos = min(off_qos, args.mbr, shaped_limit(args.mbr, args.inner_len))
        exp_nq = min(off_nq, args.non_qos_rate, shaped_limit(args.non_qos_rate, args.inner_len))

        g_share = green_share(pkts_qos, args.dur)
        exp_g = min(off_qos, args.gbr) / exp_qos
        qos_ok = (
            close(out_qos, exp_qos, tol=0.08)
            and g_share is not None
            and abs(g_share - exp_g) <= 0.10
            and all(x["ip_ok"] for x in pkts_qos)
        )
        nq_all_tos0 = bool(pkts_nq) and all((x["tos"] & 0xFC) == TOS_NONQOS and x["ip_ok"] for x in pkts_nq)
        nq_ok = close(out_nq, exp_nq, tol=0.08) and nq_all_tos0

        cls_str = ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v)
        off_qos_eff = sent[0] * args.inner_len * 8 / args.dur / 1e6
        off_nq_eff = sent[1] * args.inner_len * 8 / args.dur / 1e6

        report(
            f"isolamento - flusso QoS (TEID 9999 -> {args.green_class}/{args.yellow_class})",
            qos_ok,
            f"regime {out_qos:.2f} Mbps (atteso {exp_qos:.2f}), verde(0x88)={g_share:.2f} (atteso {exp_g:.2f}) "
            f"[offerto eff. {off_qos_eff:.1f} Mbps]",
        )
        report(
            f"isolamento - flusso Non-QoS (TEID 7771 -> {args.non_qos_class})",
            nq_ok,
            f"regime {out_nq:.2f} Mbps (atteso {exp_nq:.2f}), 100% TOS 0x00/csum={'ok' if nq_all_tos0 else 'FAIL'} "
            f"[offerto eff. {off_nq_eff:.1f} Mbps]  classi(pkt)={cls_str}",
        )
        if args.green_class and args.yellow_class and args.non_qos_class and dcls:
            tc_iso_ok = (
                dcls.get(args.green_class, 0) > 0
                and dcls.get(args.yellow_class, 0) > 0
                and dcls.get(args.non_qos_class, 0) > 0
            )
            report("isolamento - attivazione parallela classi TC", tc_iso_ok, f"classi(pkt)={cls_str}")
        wait_tc_drain(args)
    finally:
        try:
            send_cp(args, {"cmd": "delete_uplink", "teid": TEID_NONQOS_NULL})
        except Exception:
            pass


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbr", type=float, default=20.0, help="MBR del QER di TEID_UL, Mbps")
    ap.add_argument("--gbr", type=float, default=10.0, help="GBR del QER di TEID_UL, Mbps")
    ap.add_argument("--non-qos-rate", type=float, default=10.0, help="Rate dello shaper Non-QoS (1:40/1:42), Mbps")
    ap.add_argument("--inner-len", type=int, default=1000, help="lunghezza IP interno (byte)")
    ap.add_argument("--dur", type=float, default=5.0, help="durata di ogni punto dello sweep (s)")
    ap.add_argument("--tc-if", default="veth-n6", help="interfaccia con l'HTB (lato UPF)")
    ap.add_argument("--upf-ns", default="host", help="netns dell'UPF ('host' = namespace init)")
    ap.add_argument("--cp-addr", default="127.0.0.1:8805", help="indirizzo UDP Control Plane UPF")
    ap.add_argument("--green-class", default="1:21", help="classid HTB del verde (AF41), es. 1:21")
    ap.add_argument("--yellow-class", default="1:22", help="classid HTB del giallo (AF43), es. 1:22")
    ap.add_argument("--non-qos-class", default="1:42", help="classid HTB Non-QoS (CS0), es. 1:42")
    ap.add_argument("--burst-bytes", type=int, default=0, help="burst tolerance attesa (byte)")
    ap.add_argument(
        "--skip", nargs="*", default=[],
        choices=["func", "rate", "size", "burst", "recov", "nonqos", "iso"],
    )
    ap.add_argument("--htb-overhead", type=int, default=None,
                    help="byte oltre l'IP interno contati dall'HTB (default: 14 in UL; 0 con 'stab overhead')")
    args = ap.parse_args()
    global L2_OVERHEAD
    if args.htb_overhead is not None:
        L2_OVERHEAD = args.htb_overhead

    if os.geteuid() != 0:
        sys.exit("serve root")

    if "func" not in args.skip:   phase_func()
    if "rate" not in args.skip:   phase_rate(args)
    if "size" not in args.skip:   phase_size(args)
    if "burst" not in args.skip:  phase_burst(args)
    if "recov" not in args.skip:  phase_recov(args)
    if "nonqos" not in args.skip: phase_nonqos(args)
    if "iso" not in args.skip:    phase_iso(args)

    print("\n================ RIEPILOGO ================")
    for tag, name, detail in RESULTS:
        print(f"[{tag}] {name}: {detail}")
    fails = sum(1 for t, _, _ in RESULTS if t == "FAIL")
    print(f"\n{fails} FAIL su {sum(1 for t, _, _ in RESULTS if t != 'INFO')} verifiche")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()