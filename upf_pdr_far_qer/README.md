# upf_simply

Prototipo di data plane per una **UPF 5G** scritto in **Rust** con **eBPF (Aya)**.
Un programma **XDP** intercetta il traffico GTP-U, ne estrae i campi principali e li inoltra
allo userspace tramite **RingBuf**. Il progetto nasce come base per simulare
logiche di QoS della UPF (PDR, QER).

> ⚠️ Stato: prototipo / work in progress.

## Funzionalità

- Parsing in XDP di Ethernet → IPv4 → UDP (porta `2152`) → GTP-U
- Estrazione di `msg_type` e `TEID` dall'header GTP-U
- Invio delle coppie al processo userspace tramite `RingBuf` (struct `GtpPair`, definita nel crate `common`)
- Lettura e stampa degli eventi nello userspace
- Script di test con Scapy per generare pacchetti GTP-U

## Architettura

```
 Scapy ──GTP-U (UDP 2152)──▶ interfaccia (lo)
                                   │
                           [ XDP program ]  (upf_simply-ebpf)
                      Eth → IPv4 → UDP:2152 → GTP-U
                                   │  GtpPair { msg_type, teid }
                               [ RingBuf ]
                                   │
                          [ userspace loader ]  (upf_simply)
                             legge e stampa gli eventi
```

## Struttura del repository

```
upf_simply/
├── upf_simply/        # loader userspace (Aya)
├── upf_simply-ebpf/   # programma XDP (no_std)
├── common/            # tipi condivisi (GtpPair)
├── [scripts/test_gtpu.py]   # generatore di pacchetti Scapy
└── README.md
```

## Requisiti

- Linux con supporto XDP/eBPF (kernel [≥ 5.8 per RingBuf])
- Rust stable + nightly (con `rust-src`)
- `bpf-linker`: `cargo install bpf-linker`
- Privilegi di root (per caricare il programma XDP)
- Python 3 + Scapy per i test: `pip install scapy`

## Build ed esecuzione

# build (programma eBPF + userspace)
```bash
cargo build --release
```

# esecuzione sul loopback
```bash
cargo run --release --iface lo
```

## Test

In un secondo terminale:

```bash
sudo python3 scripts/test_gtpu.py
```

Output atteso nel loader:

```
[esempio] msg_type=255 teid=0x00000001
```

## Roadmap

- [ ] Gestione dei PDR (Packet Detection Rules) tramite mappe eBPF
- [ ] QER: rate limiting / simulazione QoS
- [ ] Contatori e statistiche per TEID
- [ ] Test su Raspberry Pi con interfacce reali
- [ ] [...]
