"""
Self-test DOWNLINK dell'UPF: encapsulazione GTP-U, QoS (trTCM/GCRA),
shaper TC multi-classe 3GPP/RFC 4594/GSMA IR.34 (QoS 1:21/1:22 vs Non-QoS 1:42),
anti-spoofing DSCP e isolamento.

Il test va eseguito DENTRO ns-dn:
    sudo taskset -c 2 ip netns exec ns-dn python3 scripts/upf_dl_selftest.py \
        --mbr 20 --gbr 10 --non-qos-rate 10 --tc-if veth-n3 \
        --green-class 1:21 --yellow-class 1:22 --non-qos-class 1:42 \
        --burst-bytes 15000 --htb-overhead 0

Fasi:
  1. FUNZ    encap GTP-U / policy / MTU + marcatura outer AF41 (0x88)
  2. RATE    sweep del rate offerto (trTCM + TC 1:21/1:22)
  3. SIZE    invarianza rispetto alla dimensione del pacchetto interno
  4. BURST   raffica back-to-back dopo quiete
  5. RECOV   ricarica del bucket dopo pausa
  6. NONQOS  flussi Non-QoS DL (qos=null -> QFI 0 e Non-GBR 0/0 -> QFI 7),
             anti-spoofing outer TOS 0x00 e shaper 1:42 (rate a regime su finestra temporale)
  7. ISO     isolamento parallelo DL QoS (TEID 7001 -> 1:21/1:22) vs Non-QoS (TEID 7011 -> 1:42)
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
from collections import Counter

from scapy.all import Ether, IP, UDP, Raw, PcapReader

from netns_topology import IFACE_GNB, IP_DN, UE_IP, GTP_PORT

NS_GNB = "ns-gnb"
TEID_DL = 7001               # FAR 3: peer_teid
QFI_DL = 5                   # QER 2 (5QI=2 -> AF41 0x88 / AF43 0x98)
UE_NO_PDR = "10.60.0.99"     # IP UE senza PDR nella DL_PDR_MAP
UE_NONQOS_NULL = "10.60.0.10"
TEID_NONQOS_NULL = 7010
UE_NONQOS_ZERO = "10.60.0.11"
TEID_NONQOS_ZERO = 7011
QFI_NONQOS_ZERO = 7
DL_PORT = 6000               # porta UDP del traffico utente (diversa da 2152!)
ENCAP = 44                   # IP(20)+UDP(8)+GTP(8)+campi opz.(4)+ext PDU Session(4)
L2_OVERHEAD = 14 + ENCAP     # in DL l'HTB vede Ethernet + outer header + IP interno

TOS_EF = 0xB8                # 5QI 82..85 (Real-Time EF)    -> 1:10
TOS_GREEN = 0x88             # 5QI 2 Verde (AF41)           -> 1:21
TOS_YELLOW = 0x98            # 5QI 2 Giallo (AF43)          -> 1:22
TOS_NONQOS = 0x00            # 5QI 9 / qos=null (CS0 BE)    -> 1:42

CFG = {}


def shaped_limit(rate_mbps, ip_len):
    """Rate (Mbps di IP interno) massimo in uscita dall'HTB."""
    return rate_mbps * ip_len / (ip_len + L2_OVERHEAD)


# ---------------------------------------------------------------- costruzione

def frame(sport, ip_len, dst=UE_IP, tos=0):
    """Frame Ethernet con IP 'nudo' DN -> UE, lungo esattamente ip_len byte di IP."""
    pad = max(0, ip_len - 28)
    return bytes(Ether(src=CFG["mac_dn"], dst=CFG["mac_n6"])
                 / IP(src=IP_DN, dst=dst, tos=tos) / UDP(sport=sport, dport=DL_PORT)
                 / Raw(b"x" * pad))


# ------------------------------------------------------------------ invio

_sock = None


def sock():
    global _sock
    if _sock is None:
        _sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        _sock.bind((CFG["dn_if"], 0))
    return _sock


def send_paced(fr, pps, dur):
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
    """Invia piu' flussi interleaved sullo stesso socket/CPU."""
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
    """tcpdump eredita l'affinita' del sender: lo spostiamo su altre CPU."""
    mine = os.sched_getaffinity(0)
    others = set(range(os.cpu_count())) - mine
    if others:
        os.sched_setaffinity(0, others)


def start_cap(name):
    path = f"/tmp/dl_{name}.pcap"
    log = f"/tmp/dl_{name}.log"
    for f in (path, log):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    p = subprocess.Popen(
        ["ip", "netns", "exec", NS_GNB, "tcpdump", "-Z", "root", "-i", IFACE_GNB,
         "-n", "-U", "-B", "16384", "-w", path,
         "dst", "host", CFG["outer_dst"], "and", "udp", "dst", "port", str(GTP_PORT)],
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


def inner_udp_sport(x):
    """Estrae la porta sorgente UDP del pacchetto interno (None se non e' IPv4/UDP)."""
    inner = x["inner"]
    if len(inner) < 28 or (inner[0] >> 4) != 4 or inner[9] != 17:
        return None
    ihl = (inner[0] & 0x0F) * 4
    if len(inner) < ihl + 4:
        return None
    return struct.unpack("!H", inner[ihl : ihl + 2])[0]


def read_cap(path):
    """Decodifica a mano i pacchetti GTP-U catturati in ns-gnb."""
    out = []
    for pkt in PcapReader(path):
        raw = bytes(pkt)
        if len(raw) < 14 + 20 + 8 + 8 or raw[12:14] != b"\x08\x00":
            continue
        ip = raw[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 16:
            continue
        udp = ip[ihl:]
        gtp = udp[8:]
        flags, mtype, glen, teid = struct.unpack("!BBHI", gtp[:8])
        d = dict(
            t=float(pkt.time), tos=ip[1], ttl=ip[8],
            total=struct.unpack("!H", ip[2:4])[0],
            src=socket.inet_ntoa(ip[12:16]), dst=socket.inet_ntoa(ip[16:20]),
            ip_ok=ip_csum_ok(ip[:ihl]),
            sport=struct.unpack("!H", udp[0:2])[0], dport=struct.unpack("!H", udp[2:4])[0],
            udp_len=struct.unpack("!H", udp[4:6])[0], udp_csum=struct.unpack("!H", udp[6:8])[0],
            flags=flags, mtype=mtype, glen=glen, teid=teid, qfi=None, pdu_type=None)
        off = 8
        if flags & 0x07:
            next_t = gtp[11] if len(gtp) > 11 else 0
            off = 12
            while next_t != 0 and off + 4 <= len(gtp):
                elen = gtp[off] * 4
                if elen == 0:
                    break
                if next_t == 0x85 and elen >= 4:
                    d["pdu_type"] = gtp[off + 1] >> 4
                    d["qfi"] = gtp[off + 2] & 0x3F
                next_t = gtp[off + elen - 1]
                off += elen
        d["inner"] = gtp[off:]
        d["inner_len"] = struct.unpack("!H", d["inner"][2:4])[0] if len(d["inner"]) >= 4 else 0
        out.append(d)
    return out


def check_encap(x, sent_ip, ip_len, a, exp_teid=TEID_DL, exp_qfi=QFI_DL, exp_tos=TOS_GREEN):
    """Ritorna la lista dei controlli falliti su un pacchetto incapsulato."""
    bad = []
    if not x["ip_ok"]:                          bad.append("checksum IP esterno")
    if x["src"] != a.outer_src or x["dst"] != a.outer_dst:
        bad.append("indirizzi esterni")
    if x["total"] != ip_len + ENCAP:            bad.append("lunghezza IP esterno")
    if x["sport"] != GTP_PORT or x["dport"] != GTP_PORT:
        bad.append("porte UDP")
    if x["udp_len"] != ip_len + 24:             bad.append("lunghezza UDP")
    if x["udp_csum"] != 0:                      bad.append("checksum UDP != 0")
    if x["flags"] != 0x34:                      bad.append("flag GTP")
    if x["mtype"] != 255:                       bad.append("msg type")
    if x["glen"] != ip_len + 8:                 bad.append("lunghezza GTP")
    if x["teid"] != exp_teid:                   bad.append(f"TEID ({x['teid']} != {exp_teid})")
    if x["pdu_type"] != 0:                      bad.append("PDU type (DL=0)")
    if x["qfi"] != exp_qfi:                     bad.append(f"QFI ({x['qfi']} != {exp_qfi})")
    if x["inner"] != sent_ip:                   bad.append("pacchetto interno alterato")
    if (x["tos"] & 0xFC) != exp_tos:            bad.append(f"TOS 0x{x['tos']:02x} != 0x{exp_tos:02x}")
    return bad


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


def link_mac(ifname, pre):
    out = subprocess.run(pre + ["ip", "-o", "link", "show", "dev", ifname],
                         capture_output=True, text=True).stdout
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    if not m:
        sys.exit(f"MAC di {ifname} non trovato (comando: {' '.join(pre)} ip link show dev {ifname})")
    return m.group(1)


# ---------------------------------------------------------------- misure

RESULTS = []


def report(name, ok, detail):
    tag = "PASS" if ok is True else ("FAIL" if ok is False else "INFO")
    RESULTS.append((tag, name, detail))
    print(f"  [{tag}] {name}: {detail}")


def close(val, exp, tol=0.08, floor=0.3):
    return abs(val - exp) <= max(exp * tol, floor)


def rate_mbps(pkts, dur):
    return sum(p["inner_len"] for p in pkts) * 8 / dur / 1e6


def windowed_rate_mbps(pkts, dur, warm=1.0, tail=0.3):
    """Rate (Mbps di IP interno) a regime nella finestra [t0 + warm, t0 + dur - tail],
    immune sia al burst iniziale sia allo svuotamento post-invio di fq_codel."""
    if not pkts:
        return 0.0
    t0 = pkts[0]["t"]
    a, b = t0 + warm, t0 + dur - tail
    if b <= a + 0.1:
        return rate_mbps(pkts, dur)
    sel = [p for p in pkts if a <= p["t"] <= b]
    if not sel:
        return 0.0
    return sum(p["inner_len"] for p in sel) * 8 / (b - a) / 1e6


def green_share(pkts, dur=None, warm=1.0, tail=0.3):
    """Quota di pacchetti verdi (AF41 = TOS 0x88) letta dall'header IP esterno."""
    if not pkts:
        return None
    if dur is not None:
        t0 = pkts[0]["t"]
        sel = [p for p in pkts if t0 + warm <= p["t"] <= t0 + dur - tail]
        if sel:
            pkts = sel
    return sum(1 for p in pkts if (p["tos"] & 0xFC) == TOS_GREEN) / len(pkts)


# ------------------------------------------------------------------ fasi

def phase_func(args):
    print("\n=== FASE 1: encap GTP-U / policy (basso rate, 5QI=2 -> AF41 0x88) ===")
    N = 20
    casi = [
        ("inner 200 B", 6001, 200, UE_IP, True),
        ("inner 1000 B", 6002, 1000, UE_IP, True),
        ("inner 1456 B (limite MTU: outer = 1500)", 6003, 1456, UE_IP, True),
        ("inner 1457 B (oltre MTU: niente encap)", 6004, 1457, UE_IP, False),
        ("UE senza PDR", 6005, 200, UE_NO_PDR, False),
    ]
    p, path = start_cap("func")
    sent = {}
    for nome, sport, ip_len, dst, enc in casi:
        fr = frame(sport, ip_len, dst)
        sent[sport] = fr[14:]
        send_paced(fr, 100, N / 100)
        time.sleep(0.2)
    stop_cap(p)
    pkts = read_cap(path)
    for nome, sport, ip_len, dst, enc in casi:
        got = [x for x in pkts if inner_udp_sport(x) == sport]
        if enc:
            bad = Counter()
            for x in got:
                for b in check_encap(x, sent[sport], ip_len, args):
                    bad[b] += 1
            ok = len(got) == N and not bad
            det = f"incapsulati {len(got)}/{N}"
            if bad:
                det += ", errori: " + ", ".join(f"{k} x{v}" for k, v in bad.items())
            report(nome, ok, det)
        else:
            report(nome, len(got) == 0, f"incapsulati {len(got)} (atteso 0)")
    if not pkts:
        print("\n  Nessun pacchetto GTP-U in ns-gnb. Controlla: ip_forward, rotta verso "
              "10.0.3.2, QER 2, e rp_filter/accept_local.")


def run_rate(args, offered_mbps, ip_len, dur, tag):
    global LAST_OFFERED
    pps = offered_mbps * 1e6 / 8 / ip_len
    fr = frame(6100, ip_len)
    before = tc_classes(args)
    p, path = start_cap(tag)
    n_sent = send_paced(fr, pps, dur)
    LAST_OFFERED = n_sent * ip_len * 8 / dur / 1e6
    stop_cap(p)
    after = tc_classes(args)
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL and inner_udp_sport(x) == 6100]
    return rate_mbps(pkts, dur), tc_delta(before, after), len(pkts), green_share(pkts)


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
            exp_share = min(off, gbr) / exp
            okt = abs(share_tos - exp_share) <= 0.10
            extra += f"  verde(TOS 0x88)={share_tos:.2f} (atteso {exp_share:.2f}) {'ok' if okt else 'FUORI'}"
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
               f"uscita {out:6.2f} Mbps, atteso {exp:6.2f}{extra}  "
               f"[offerto eff. {LAST_OFFERED:.1f} Mbps, tcpdump: {LAST_CAP}]")
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
    fr = frame(6200, 1000)
    p, path = start_cap("burst")
    _, el = send_burst(fr, n)
    stop_cap(p)
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL and inner_udp_sport(x) == 6200]
    byt = sum(x["inner_len"] for x in pkts)
    msg = (f"inviati {n} pacchetti da 1000 B back-to-back in {el * 1000:.1f} ms, "
           f"usciti {len(pkts)} ({byt} B di IP interno)")
    if args.burst_bytes:
        exp = args.burst_bytes + args.mbr * 1e6 / 8 * el
        tol = max(2000, 0.05 * exp)
        report("burst tolerance", abs(byt - exp) <= tol,
               msg + f", atteso ~{exp:.0f} B (burst {args.burst_bytes} + ricarica durante l'invio)")
    else:
        report("burst tolerance", None, msg + " (passa --burst-bytes per un verdetto)")


def phase_recov(args):
    print("\n=== FASE 5: ricarica del bucket dopo pausa ===")
    send_burst(frame(6300, 1000), 400)
    time.sleep(3.0)
    p, path = start_cap("recov")
    send_burst(frame(6301, 200), 1)
    stop_cap(p)
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL and inner_udp_sport(x) == 6301]
    report("pacchetto dopo pausa", len(pkts) == 1, f"usciti {len(pkts)}/1")


def phase_nonqos(args):
    print(f"\n=== FASE 6: Non-QoS DL (qos=null e Non-GBR 0/0) + Anti-Spoofing + Shaper {args.non_qos_class} ===")
    try:
        r1 = send_cp(args, {
            "cmd": "add_downlink", "ue_ip": UE_NONQOS_NULL, "far_id": 201,
            "far_action": "forward", "peer_ip": args.outer_dst,
            "peer_teid": TEID_NONQOS_NULL, "local_ip": args.outer_src, "qos": None,
        })
        r2 = send_cp(args, {
            "cmd": "add_downlink", "ue_ip": UE_NONQOS_ZERO, "far_id": 202,
            "far_action": "forward", "peer_ip": args.outer_dst,
            "peer_teid": TEID_NONQOS_ZERO, "local_ip": args.outer_src,
            "qos": {"qer_id": 202, "qfi": QFI_NONQOS_ZERO, "gbr_mbps": 0, "mbr_mbps": 0},
        })
        if not (r1.get("ok") and r2.get("ok")):
            report("setup CP Non-QoS DL", False, f"r1={r1}, r2={r2}")
            return

        # 6a. Encap Non-QoS + anti-spoofing: inner IP pre-marcato AF41 (0x88) / EF (0xB8) -> outer TOS 0x00
        N = 20
        casi = [
            ("DL Non-QoS qos=null (QFI 0, inner 0x88 -> outer 0x00)",
             6401, 500, UE_NONQOS_NULL, TEID_NONQOS_NULL, 0, TOS_GREEN),
            (f"DL Non-QoS Non-GBR 0/0 (QFI {QFI_NONQOS_ZERO}, inner 0xB8 -> outer 0x00)",
             6402, 500, UE_NONQOS_ZERO, TEID_NONQOS_ZERO, QFI_NONQOS_ZERO, TOS_EF),
        ]
        before = tc_classes(args)
        p, path = start_cap("nonqos_spoof")
        sent = {}
        for _, sport, ip_len, dst, _, _, in_tos in casi:
            fr = frame(sport, ip_len, dst=dst, tos=in_tos)
            sent[sport] = fr[14:]
            send_paced(fr, 100, N / 100)
            time.sleep(0.2)
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = read_cap(path)

        for nome, sport, ip_len, _, exp_teid, exp_qfi, _ in casi:
            got = [x for x in pkts if inner_udp_sport(x) == sport]
            bad = Counter()
            for x in got:
                for b in check_encap(x, sent[sport], ip_len, args,
                                     exp_teid=exp_teid, exp_qfi=exp_qfi, exp_tos=TOS_NONQOS):
                    bad[b] += 1
            det = f"incapsulati {len(got)}/{N}"
            if bad:
                det += ", errori: " + ", ".join(f"{k} x{v}" for k, v in bad.items())
            report(nome, len(got) == N and not bad, det)

        if args.non_qos_class and dcls:
            nq_pkts = dcls.get(args.non_qos_class, 0)
            g_pkts = dcls.get(args.green_class, 0) if args.green_class else 0
            y_pkts = dcls.get(args.yellow_class, 0) if args.yellow_class else 0
            ef_pkts = dcls.get("1:10", 0)
            af11_pkts = dcls.get("1:41", 0)
            report(
                f"anti-spoofing TC DL routing ({args.non_qos_class})",
                nq_pkts >= 2 * N and g_pkts == 0 and y_pkts == 0 and ef_pkts == 0 and af11_pkts == 0,
                f"classi(pkt)=" + ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v),
            )

        # 6b. Saturazione shaper Non-QoS DL (offerto = 2 * non_qos_rate, misura a regime su finestra)
        time.sleep(1.0)
        off = 2.0 * args.non_qos_rate
        pps = off * 1e6 / 8 / args.inner_len
        fr = frame(6410, args.inner_len, dst=UE_NONQOS_ZERO, tos=TOS_GREEN)
        before = tc_classes(args)
        p, path = start_cap("nonqos_rate")
        n_sent = send_paced(fr, pps, args.dur)
        off_eff = n_sent * args.inner_len * 8 / args.dur / 1e6
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = [x for x in read_cap(path) if x["teid"] == TEID_NONQOS_ZERO and inner_udp_sport(x) == 6410]

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
            f"Non-QoS DL saturazione {off:.1f} Mbps -> shaper {args.non_qos_class}",
            close(out, exp, tol=0.08) and all_tos0 and tc_ok,
            f"regime {out:.2f} Mbps (atteso {exp:.2f}), 100% outer TOS 0x00/csum={'ok' if all_tos0 else 'FAIL'}, "
            f"classi(pkt)=" + ", ".join(f"{c}:{v}" for c, v in sorted(dcls.items()) if v)
            + f"  [offerto eff. {off_eff:.1f} Mbps, tcpdump: {LAST_CAP}]",
        )
        wait_tc_drain(args)
    finally:
        for ue in (UE_NONQOS_NULL, UE_NONQOS_ZERO):
            try:
                send_cp(args, {"cmd": "delete_downlink", "ue_ip": ue})
            except Exception:
                pass


def phase_iso(args):
    print(f"\n=== FASE 7: Isolamento parallelo DL QoS ({args.green_class}/{args.yellow_class}) vs Non-QoS ({args.non_qos_class}) ===")
    try:
        r = send_cp(args, {
            "cmd": "add_downlink", "ue_ip": UE_NONQOS_ZERO, "far_id": 202,
            "far_action": "forward", "peer_ip": args.outer_dst,
            "peer_teid": TEID_NONQOS_ZERO, "local_ip": args.outer_src,
            "qos": {"qer_id": 202, "qfi": QFI_NONQOS_ZERO, "gbr_mbps": 0, "mbr_mbps": 0},
        })
        if not r.get("ok"):
            report("setup CP isolamento DL", False, f"resp={r}")
            return

        wait_tc_drain(args)
        time.sleep(1.5)
        off_qos = 1.5 * args.mbr
        off_nq = 2.0 * args.non_qos_rate
        pps_qos = off_qos * 1e6 / 8 / args.inner_len
        pps_nq = off_nq * 1e6 / 8 / args.inner_len

        fr_qos = frame(6501, args.inner_len, dst=UE_IP, tos=0x00)
        fr_nq = frame(6502, args.inner_len, dst=UE_NONQOS_ZERO, tos=TOS_GREEN)

        before = tc_classes(args)
        p, path = start_cap("iso")
        sent = send_paced_multi([(fr_qos, pps_qos), (fr_nq, pps_nq)], args.dur)
        stop_cap(p)
        after = tc_classes(args)
        dcls = tc_delta(before, after)
        pkts = read_cap(path)

        pkts_qos = [x for x in pkts if x["teid"] == TEID_DL and inner_udp_sport(x) == 6501]
        pkts_nq = [x for x in pkts if x["teid"] == TEID_NONQOS_ZERO and inner_udp_sport(x) == 6502]

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
            f"isolamento DL - flusso QoS (TEID 7001 -> {args.green_class}/{args.yellow_class})",
            qos_ok,
            f"regime {out_qos:.2f} Mbps (atteso {exp_qos:.2f}), verde(0x88)={g_share:.2f} (atteso {exp_g:.2f}) "
            f"[offerto eff. {off_qos_eff:.1f} Mbps]",
        )
        report(
            f"isolamento DL - flusso Non-QoS (TEID 7011 -> {args.non_qos_class})",
            nq_ok,
            f"regime {out_nq:.2f} Mbps (atteso {exp_nq:.2f}), 100% outer TOS 0x00/csum={'ok' if nq_all_tos0 else 'FAIL'} "
            f"[offerto eff. {off_nq_eff:.1f} Mbps]  classi(pkt)={cls_str}",
        )
        if args.green_class and args.yellow_class and args.non_qos_class and dcls:
            tc_iso_ok = (
                dcls.get(args.green_class, 0) > 0
                and dcls.get(args.yellow_class, 0) > 0
                and dcls.get(args.non_qos_class, 0) > 0
            )
            report("isolamento DL - attivazione parallela classi TC", tc_iso_ok, f"classi(pkt)={cls_str}")
        wait_tc_drain(args)
    finally:
        try:
            send_cp(args, {"cmd": "delete_downlink", "ue_ip": UE_NONQOS_ZERO})
        except Exception:
            pass


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbr", type=float, default=20.0, help="MBR del QER DL, Mbps")
    ap.add_argument("--gbr", type=float, default=10.0, help="GBR del QER DL, Mbps")
    ap.add_argument("--non-qos-rate", type=float, default=10.0, help="Rate dello shaper Non-QoS (1:40/1:42), Mbps")
    ap.add_argument("--inner-len", type=int, default=1000, help="lunghezza IP interno (byte)")
    ap.add_argument("--dur", type=float, default=5.0, help="durata di ogni punto dello sweep (s)")
    ap.add_argument("--tc-if", default="veth-n3", help="interfaccia con l'HTB per il DL (lato UPF)")
    ap.add_argument("--upf-ns", default="host", help="netns dell'UPF ('host' = namespace init)")
    ap.add_argument("--cp-addr", default="127.0.0.1:8805", help="indirizzo UDP Control Plane UPF")
    ap.add_argument("--n6-if", default="veth-n6", help="interfaccia N6 dell'UPF (dove e' attaccato XDP)")
    ap.add_argument("--dn-if", default="veth-dn", help="interfaccia del sender dentro ns-dn")
    ap.add_argument("--outer-src", default="10.0.3.1", help="local_ip del FAR 3")
    ap.add_argument("--outer-dst", default="10.0.3.2", help="peer_ip del FAR 3")
    ap.add_argument("--green-class", default="1:21", help="classid HTB del verde (AF41), es. 1:21")
    ap.add_argument("--yellow-class", default="1:22", help="classid HTB del giallo (AF43), es. 1:22")
    ap.add_argument("--non-qos-class", default="1:42", help="classid HTB Non-QoS (CS0), es. 1:42")
    ap.add_argument("--burst-bytes", type=int, default=0, help="burst tolerance attesa (byte)")
    ap.add_argument(
        "--skip", nargs="*", default=[],
        choices=["func", "rate", "size", "burst", "recov", "nonqos", "iso"],
    )
    ap.add_argument("--htb-overhead", type=int, default=None,
                    help="byte oltre l'IP interno contati dall'HTB (default: 58 in DL; 0 con 'stab overhead')")
    args = ap.parse_args()
    global L2_OVERHEAD
    if args.htb_overhead is not None:
        L2_OVERHEAD = args.htb_overhead

    if os.geteuid() != 0:
        sys.exit("serve root")

    CFG["dn_if"] = args.dn_if
    CFG["outer_dst"] = args.outer_dst
    CFG["mac_dn"] = link_mac(args.dn_if, [])
    CFG["mac_n6"] = link_mac(args.n6_if, upf_prefix(args))
    print(f"MAC sender ({args.dn_if}) = {CFG['mac_dn']}, MAC UPF N6 ({args.n6_if}) = {CFG['mac_n6']}")

    if "func" not in args.skip:   phase_func(args)
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