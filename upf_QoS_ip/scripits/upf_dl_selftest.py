"""
Self-test DOWNLINK dell'UPF: encapsulazione GTP-U, QoS (trTCM/GCRA) e shaper TC.
E' il duale di upf_ul_selftest.py.

Istanza UPF per il downlink (XDP su N6, shaper HTB su N3):
    sudo ./upf_simply --iface-in veth-n6 --iface-out veth-n3 --mbr 20 --gbr 10

Il test va eseguito DENTRO ns-dn (fa da Data Network e genera IP "nudo"
verso l'IP dell'UE):
    sudo taskset -c 2 ip netns exec ns-dn python3 upf_dl_selftest.py \
        --mbr 20 --gbr 10 --tc-if veth-n3 \
        --green-class 1:10 --yellow-class 1:20 --burst-bytes 15000 --htb-overhead 0

Cattura: tcpdump in ns-gnb (su IFACE_GNB), solo UDP porta 2152, su altre CPU.

Fasi:
  1. FUNZ   encap: struttura completa dell'outer header (IP, UDP, GTP-U,
            extension header PDU Session Container con QFI), pacchetto interno
            identico a quello inviato, limite MTU (inner 1456 B passa, 1457 B no),
            UE senza PDR
  2. RATE   sweep del rate offerto: uscita attesa = min(offerto, MBR); quota
            di verde (TOS esterno 0) attesa = min(offerto, GBR)/min(offerto, MBR)
  3. SIZE   invarianza rispetto alla dimensione del pacchetto interno
  4. BURST  raffica back-to-back dopo quiete (burst + ricarica durante l'invio)
  5. RECOV  dopo una pausa un pacchetto passa

Prerequisiti che il test NON verifica (se la cattura e' vuota controllali):
  - QER del DL con cir_dl/pir_dl valorizzati (se sono a 0 tutto e' verde e
    nessun pacchetto viene limitato);
  - ip_forward=1 sull'UPF e rotta verso 10.0.3.2 via veth-n3;
  - l'outer header ha come sorgente un IP locale dell'UPF: se compare 'pkts
    incapsulati' ma in ns-gnb non arriva nulla, prova sull'UPF
        sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.veth-n6.rp_filter=0
        sysctl -w net.ipv4.conf.all.accept_local=1 net.ipv4.conf.veth-n6.accept_local=1
"""

import argparse
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
QFI_DL = 5                   # QER 2
UE_NO_PDR = "10.60.0.99"     # IP UE senza PDR nella DL_PDR_MAP
DL_PORT = 6000               # porta UDP del traffico utente (diversa da 2152!)
ENCAP = 44                   # IP(20)+UDP(8)+GTP(8)+campi opz.(4)+ext PDU Session(4)
L2_OVERHEAD = 14 + ENCAP     # in DL l'HTB vede Ethernet + outer header + IP interno
CFG = {}

def shaped_limit(mbr, ip_len):
    """Rate (Mbps di IP interno) massimo in uscita dall'HTB: i suoi rate sono
    in byte di frame (Ethernet + eventuale outer header), il policer XDP conta
    solo l'IP interno. Con pacchetti piccoli l'overhead pesa di piu'."""
    return mbr * ip_len / (ip_len + L2_OVERHEAD)

# ---------------------------------------------------------------- costruzione

def frame(sport, ip_len, dst=UE_IP):
    """Frame Ethernet con IP 'nudo' DN -> UE, lungo esattamente ip_len byte di IP."""
    pad = max(0, ip_len - 28)
    return bytes(Ether(src=CFG["mac_dn"], dst=CFG["mac_n6"])
                 / IP(src=IP_DN, dst=dst) / UDP(sport=sport, dport=DL_PORT)
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
         "-n", "-U", "-B", "16384", "-w", path, "udp", "dst", "port", str(GTP_PORT)],
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
        if flags & 0x07:                      # E, S o PN: 4 byte opzionali
            next_t = gtp[11] if len(gtp) > 11 else 0
            off = 12
            while next_t != 0 and off + 4 <= len(gtp):   # catena di extension header
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

def check_encap(x, sent_ip, ip_len, a):
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
    if x["teid"] != TEID_DL:                    bad.append("TEID")
    if x["pdu_type"] != 0:                      bad.append("PDU type (DL=0)")
    if x["qfi"] != QFI_DL:                      bad.append("QFI")
    if x["inner"] != sent_ip:                   bad.append("pacchetto interno alterato")
    if x["tos"] != 0:                           bad.append("TOS != 0 (verde atteso)")
    return bad

# --------------------------------------------------------------------- tc

def upf_prefix(args):
    if args.upf_ns == "host":
        return ["nsenter", "-t", "1", "-n"]
    return ["ip", "netns", "exec", args.upf_ns]

def tc_classes(args):
    """Ritorna {classid: pacchetti} da `tc -s class show`."""
    try:
        txt = subprocess.run(upf_prefix(args) + ["tc", "-s", "class", "show", "dev", args.tc_if],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return {}
    res = {}
    for blk in txt.split("class htb ")[1:]:
        cid = blk.split()[0]
        m = re.search(r"Sent (\d+) bytes (\d+) pkt", blk)
        if m:
            res[cid] = int(m.group(2))
    return res

def tc_delta(before, after):
    return {c: after.get(c, 0) - before.get(c, 0) for c in after}

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
    """Rate dell'IP interno = byte totali catturati / durata dell'invio."""
    return sum(p["inner_len"] for p in pkts) * 8 / dur / 1e6

def green_share(pkts):
    if not pkts:
        return None
    return sum(1 for p in pkts if p["tos"] == 0x00) / len(pkts)

# ------------------------------------------------------------------ fasi

def phase_func(args):
    print("\n=== FASE 1: encap GTP-U / policy (basso rate) ===")
    N = 20
    casi = [
        # nome, sport, ip_len, dst, atteso_encap
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
        # il pacchetto interno e' riconoscibile dalla porta UDP sorgente interna
        got = [x for x in pkts if len(x["inner"]) >= 28
               and struct.unpack("!H", x["inner"][20:22])[0] == sport]
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
              "10.0.3.2, QER 2, e rp_filter/accept_local (vedi il docstring).")

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
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL]
    return rate_mbps(pkts, dur), tc_delta(before, after), len(pkts), green_share(pkts)

def phase_rate(args):
    print("\n=== FASE 2: sweep del rate offerto (trTCM + TC) ===")
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
            extra += f"  verde(TOS 0)={share_tos:.2f} (atteso {exp_share:.2f}) {'ok' if okt else 'FUORI'}"
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
        lim = shaped_limit(args.mbr, size)   # l'HTB conta anche L2/encap
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
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL]
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
    pkts = [x for x in read_cap(path) if x["teid"] == TEID_DL]
    report("pacchetto dopo pausa", len(pkts) == 1, f"usciti {len(pkts)}/1")

# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbr", type=float, default=20.0, help="MBR del QER DL, Mbps")
    ap.add_argument("--gbr", type=float, default=10.0, help="GBR del QER DL, Mbps")
    ap.add_argument("--inner-len", type=int, default=1000, help="lunghezza IP interno (byte)")
    ap.add_argument("--dur", type=float, default=5.0, help="durata di ogni punto dello sweep (s)")
    ap.add_argument("--tc-if", default="veth-n3", help="interfaccia con l'HTB per il DL (lato UPF)")
    ap.add_argument("--upf-ns", default="host", help="netns dell'UPF ('host' = namespace init)")
    ap.add_argument("--n6-if", default="veth-n6", help="interfaccia N6 dell'UPF (dove e' attaccato XDP)")
    ap.add_argument("--dn-if", default="veth-dn", help="interfaccia del sender dentro ns-dn")
    ap.add_argument("--outer-src", default="10.0.3.1", help="local_ip del FAR 3")
    ap.add_argument("--outer-dst", default="10.0.3.2", help="peer_ip del FAR 3")
    ap.add_argument("--green-class", default=None, help="classid HTB del verde, es. 1:10")
    ap.add_argument("--yellow-class", default=None, help="classid HTB del giallo, es. 1:20")
    ap.add_argument("--burst-bytes", type=int, default=0, help="burst tolerance attesa (byte)")
    ap.add_argument("--skip", nargs="*", default=[], choices=["func", "rate", "size", "burst", "recov"])
    ap.add_argument("--htb-overhead", type=int, default=None,
                    help="byte oltre l'IP interno contati dall'HTB (default: valore naturale, "
                         "14 in UL e 58 in DL; 0 se l'HTB usa 'stab overhead' negativo)")
    args = ap.parse_args()
    global L2_OVERHEAD
    if args.htb_overhead is not None:
        L2_OVERHEAD = args.htb_overhead

    if os.geteuid() != 0:
        sys.exit("serve root")

    CFG["dn_if"] = args.dn_if
    CFG["mac_dn"] = link_mac(args.dn_if, [])
    CFG["mac_n6"] = link_mac(args.n6_if, upf_prefix(args))
    print(f"MAC sender ({args.dn_if}) = {CFG['mac_dn']}, MAC UPF N6 ({args.n6_if}) = {CFG['mac_n6']}")

    if "func" not in args.skip:  phase_func(args)
    if "rate" not in args.skip:  phase_rate(args)
    if "size" not in args.skip:  phase_size(args)
    if "burst" not in args.skip: phase_burst(args)
    if "recov" not in args.skip: phase_recov(args)

    print("\n================ RIEPILOGO ================")
    for tag, name, detail in RESULTS:
        print(f"[{tag}] {name}: {detail}")
    fails = sum(1 for t, _, _ in RESULTS if t == "FAIL")
    print(f"\n{fails} FAIL su {sum(1 for t, _, _ in RESULTS if t != 'INFO')} verifiche")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()