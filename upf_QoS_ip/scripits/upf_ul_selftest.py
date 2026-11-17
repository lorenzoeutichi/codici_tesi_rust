"""
Self-test UPLINK dell'UPF: parsing GTP-U, decap, QoS (trTCM/GCRA) e shaper TC.

Va eseguito DENTRO ns-gnb, come il test di decap:
    sudo ip netns exec ns-gnb python3 upf_ul_selftest.py --mbr 20 --gbr 10 \
        --tc-if veth-n6 --green-class 1:10 --yellow-class 1:20 --htb-overhead 0

Lo script:
  - invia traffico GTP-U da ns-gnb con un socket AF_PACKET (molto piu' veloce
    di sendp() per ogni pacchetto) e con pacing a rate controllato;
  - cattura l'uscita in ns-dn con tcpdump (ip netns exec ns-dn ...);
  - legge i contatori delle classi HTB con `tc -s class show` prima/dopo ogni
    fase e ne fa la differenza (e' il modo per vedere verde/giallo);
  - stampa un riepilogo PASS/FAIL.

Fasi:
  1. FUNZ   parsing/decap: casi con diversi flag/extension header + casi che
            non devono uscire (TEID DROP, TEID senza PDR)
  2. RATE   sweep del rate offerto (sotto GBR, tra GBR e MBR, sopra MBR):
            rate in uscita atteso = min(offerto, MBR); quota verde attesa =
            min(offerto, GBR) / min(offerto, MBR)
  3. SIZE   invarianza rispetto alla dimensione del pacchetto (il costo e'
            la lunghezza dell'IP interno, non l'overhead GTP)
  4. BURST  raffica back-to-back dopo un periodo di quiete: quanti pacchetti
            passano (da confrontare con la burst tolerance configurata)
  5. RECOV  dopo una pausa il bucket si ricarica e un pacchetto passa

Assunzioni (modificabili da riga di comando / costanti):
  - il pacchetto uscente su veth-dn e' IP "nudo" (UDP verso la porta 5000);
  - le classi HTB: verde e giallo sono due classi distinte (--green-class,
    --yellow-class); se non le passi, i delta delle classi vengono solo stampati;
  - le lunghezze in gioco sono quelle dell'IP interno (come nel tuo policing).
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

from scapy.all import Ether, IP, UDP, Raw, PcapReader

from netns_topology import (
    IFACE_GNB, MAC_GNB, MAC_N3, IP_GNB, IP_N3, IP_DN,
    UE_IP, TEID_UL, TEID_UL_DROP, GTP_PORT,
)

DN_PORT = 5000
NS_DN = "ns-dn"
IFACE_DN = "veth-dn"
TEID_NO_PDR = 55555          # TEID che NON ha PDR installato

EXT_PDU_SESSION = 0x85
EXT_UDP_PORT = 0x40
L2_OVERHEAD = 14             # in UL l'HTB vede IP interno + header Ethernet

def shaped_limit(mbr, ip_len):
    """Rate (Mbps di IP interno) massimo in uscita dall'HTB: i suoi rate sono
    in byte di frame (Ethernet + eventuale outer header), il policer XDP conta
    solo l'IP interno. Con pacchetti piccoli l'overhead pesa di piu'."""
    return mbr * ip_len / (ip_len + L2_OVERHEAD)

# ---------------------------------------------------------------- costruzione

def gtp_u(flags, body=b"", teid=TEID_UL, msg_type=255):
    return struct.pack("!BBHI", flags, msg_type, len(body), teid) + body

def opt(next_type=0, seq=1, npdu=0):
    return struct.pack("!HBB", seq, npdu, next_type)

def ext_pdu_session(qfi, next_type=0, pdu_type=0):
    return struct.pack("!BBBB", 1, pdu_type << 4, qfi & 0x3F, next_type)

def ext_riempitivo(next_type):
    return struct.pack("!BHB", 1, GTP_PORT, next_type)

def inner_packet(sport, ip_len=None, text=b"ping-dn"):
    """IP interno UE -> DN. Se ip_len e' dato, il payload UDP viene
    riempito in modo che la lunghezza totale IP sia esattamente ip_len."""
    if ip_len is not None:
        pad = max(0, ip_len - 28)
        text = (b"x" * pad)[:pad]
    return bytes(IP(src=UE_IP, dst=IP_DN) / UDP(sport=sport, dport=DN_PORT) / Raw(text))

def frame(gtp_payload):
    return bytes(Ether(src=MAC_GNB, dst=MAC_N3) / IP(src=IP_GNB, dst=IP_N3)
                 / UDP(sport=50000, dport=GTP_PORT) / Raw(gtp_payload))

def ul_frame(sport, ip_len=None, teid=TEID_UL, qfi=5):
    """Caso 'standard' per i test di rate: E flag + PDU Session Container."""
    body = opt(EXT_PDU_SESSION) + ext_pdu_session(qfi) + inner_packet(sport, ip_len)
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

def send_burst(fr, count):
    s = sock()
    t0 = time.perf_counter()
    for _ in range(count):
        s.send(fr)
    return count, time.perf_counter() - t0

# ---------------------------------------------------------------- cattura

LAST_CAP = None   # (pacchetti catturati, drop del kernel) dell'ultima cattura
LAST_OFFERED = 0.0  # rate realmente offerto dal sender nell'ultima fase (Mbps)

def _cap_affinity():
    """tcpdump eredita l'affinita' del sender (taskset): lo spostiamo su altre CPU,
    cosi' non compete con sender + XDP + TC, che girano tutti sulla CPU fissata."""
    mine = os.sched_getaffinity(0)
    others = set(range(os.cpu_count())) - mine
    if others:
        os.sched_setaffinity(0, others)

def start_cap(name):
    path = f"/tmp/ul_{name}.pcap"
    log = f"/tmp/ul_{name}.log"
    for f in (path, log):                  # mai leggere un pcap di un run precedente
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

def read_cap(path):
    """Ritorna lista di dict: t, ip_len, sport, key (campi confrontabili)."""
    out = []
    for pkt in PcapReader(path):
        raw = bytes(pkt)
        if len(raw) < 14 + 20 or raw[12:14] != b"\x08\x00":
            continue
        ip = raw[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        if ip[9] != 17:
            continue
        sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
        payload = ip[ihl + 8:total]
        out.append(dict(t=float(pkt.time), ip_len=total, sport=sport, tos=ip[1],
                        key=(ip[12:16], ip[16:20], total, sport, dport, payload)))
    return out

# --------------------------------------------------------------------- tc

def tc_classes(args):
    """Ritorna {classid: pacchetti} letti da `tc -s class show`."""
    if args.upf_ns == "host":
        pre = ["nsenter", "-t", "1", "-n"]
    else:
        pre = ["ip", "netns", "exec", args.upf_ns]
    try:
        txt = subprocess.run(pre + ["tc", "-s", "class", "show", "dev", args.tc_if],
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

# -------------------------------------------------------------- misure

def steady_rate_mbps(pkts, dur, warm=1.0, tail=0.3):
    """Rate (Mbps di IP interno) = byte totali catturati / durata dell'invio.
    Non dipende dal timestamp del primo pacchetto; il burst iniziale (circa
    15 kB) pesa meno di 0.03 Mbps su 4-5 s."""
    return sum(p["ip_len"] for p in pkts) * 8 / dur / 1e6

def green_share(pkts, dur, warm=1.0, tail=0.3):
    """Quota di pacchetti verdi (TOS 0x00) a regime, letta dal TOS dell'IP uscente.
    Il giallo e' marcato dall'XDP con DSCP 14 (TOS 0x38)."""
    if not pkts:
        return None
    t0 = pkts[0]["t"]
    sel = [p for p in pkts if t0 + warm <= p["t"] <= t0 + dur - tail]
    if not sel:
        return None
    return sum(1 for p in sel if p["tos"] == 0x00) / len(sel)

RESULTS = []

def report(name, ok, detail):
    tag = "PASS" if ok is True else ("FAIL" if ok is False else "INFO")
    RESULTS.append((tag, name, detail))
    print(f"  [{tag}] {name}: {detail}")

def close(val, exp, tol=0.08, floor=0.3):
    return abs(val - exp) <= max(exp * tol, floor)

# ------------------------------------------------------------------ fasi

def phase_func():
    print("\n=== FASE 1: parsing / decap / policy (basso rate) ===")
    N = 20
    casi = [
        # nome, sport interno, frame, atteso_forward
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
        send_paced(fr, 100, N / 100)       # ~N pacchetti a 100 pps
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
                    if x["key"][2] == len(ref) and x["key"][5] == ref_pl
                    and x["key"][0] == socket.inet_aton(ref_ip.src)
                    and x["key"][1] == socket.inet_aton(ref_ip.dst)]
            report(nome, len(good) == N and len(got) == N,
                   f"usciti {len(got)}/{N}, contenuto corretto {len(good)}/{N}")
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
    print("\n=== FASE 2: sweep del rate offerto (trTCM + TC) ===")
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
            extra += f"  verde(TOS 0)={share_tos:.2f} (atteso {exp_share_t:.2f}) {'ok' if okt else 'FUORI'}"
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
        time.sleep(2.0)                    # ricarica del bucket tra le fasi

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
    fr = ul_frame(4200, 1000)
    p, path = start_cap("burst")
    _, el = send_burst(fr, n)
    stop_cap(p)
    pkts = read_cap(path)
    byt = sum(x["ip_len"] for x in pkts)
    msg = f"inviati {n} pacchetti da 1000 B back-to-back in {el * 1000:.1f} ms, usciti {len(pkts)} ({byt} B di IP interno)"
    if args.burst_bytes:
        # GCRA: passano burst + quanto il bucket si ricarica mentre il sender sta ancora inviando
        exp = args.burst_bytes + args.mbr * 1e6 / 8 * el
        tol = max(2000, 0.05 * exp)
        report("burst tolerance", abs(byt - exp) <= tol,
               msg + f", atteso ~{exp:.0f} B (burst {args.burst_bytes} + ricarica durante l'invio)")
    else:
        report("burst tolerance", None, msg + " (passa --burst-bytes per un verdetto)")

def phase_recov(args):
    print("\n=== FASE 5: ricarica del bucket dopo pausa ===")
    send_burst(ul_frame(4300, 1000), 400)  # svuota il bucket
    time.sleep(3.0)
    p, path = start_cap("recov")
    send_burst(ul_frame(4301, 200), 1)
    stop_cap(p)
    pkts = [x for x in read_cap(path) if x["sport"] == 4301]
    report("pacchetto dopo pausa", len(pkts) == 1, f"usciti {len(pkts)}/1")

# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbr", type=float, default=20.0, help="MBR del QER di TEID_UL, Mbps")
    ap.add_argument("--gbr", type=float, default=10.0, help="GBR del QER di TEID_UL, Mbps")
    ap.add_argument("--inner-len", type=int, default=1000, help="lunghezza IP interno (byte)")
    ap.add_argument("--dur", type=float, default=5.0, help="durata di ogni punto del sweep (s)")
    ap.add_argument("--tc-if", default="veth-n6", help="interfaccia con l'HTB (lato UPF)")
    ap.add_argument("--upf-ns", default="host", help="netns dell'UPF ('host' = namespace init)")
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

    if "func" not in args.skip:  phase_func()
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