# upf_PDR/FAR

Prototipo di data plane per una **UPF 5G** scritto in **Rust** con **eBPF (Aya)**.
Un programma **XDP** intercetta il traffico GTP-U, ne estrae `msg_type` e `TEID`, cerca il TEID
nelle regole **PDR/FAR** caricate in mappe eBPF e decide se lasciar passare o scartare il pacchetto.
Gli eventi arrivano allo userspace tramite **RingBuf**, mentre l'esito di ogni pacchetto viene
conteggiato in una mappa per-CPU. Il progetto nasce come base per simulare le logiche di QoS
della UPF (PDR, FAR, QER).

> ⚠️ Stato: prototipo / work in progress.

## Funzionalità

- Parsing in XDP di Ethernet → IPv4 → UDP (porta `2152`) → GTP-U v1
- Estrazione di `msg_type` e `TEID` dall'header GTP-U
- Invio degli eventi allo userspace tramite `RingBuf` (struct `GtpPair`, definita nel crate `common`)
- **Tabella PDR** (`PDR_MAP`, chiave TEID) e **tabella FAR** (`FAR_MAP`, chiave `far_id`) in mappe eBPF, popolate dallo userspace prima dell'attach
- Azioni FAR `FORWARD` (`XDP_PASS`) e `DROP` (`XDP_DROP`)
- **Contatori per esito** (`PerCpuArray`): forward, drop per FAR, nessun PDR, nessun FAR; stampati ogni 2 secondi e all'uscita
- Script di test con Scapy per generare pacchetti GTP-U con TEID diversi

## Architettura

```
 Scapy ──GTP-U (UDP 2152)──▶ interfaccia (lo)
                                   │
                           [ XDP program ]  (upf_simply-ebpf)
                      Eth → IPv4 → UDP:2152 → GTP-U
                                   │
                    msg_type = 255 (G-PDU)?  ── no ──▶ XDP_PASS
                                   │ sì
                          PDR_MAP[TEID] ── assente ──▶ contatore "nessun PDR", XDP_PASS
                                   │
                        FAR_MAP[far_id] ── assente ──▶ contatore "nessun FAR", XDP_PASS
                                   │
                              action FAR
                        ┌──────────┴──────────┐
                    FORWARD               DROP / altro
              contatore forward     contatore drop (FAR)
                   XDP_PASS               XDP_DROP

            (ogni GTP-U valido) GtpPair { msg_type, teid }
                                   │
                               [ RingBuf ]
                                   │
                          [ userspace loader ]  (upf_simply)
              popola PDR/FAR, legge e stampa gli eventi e i contatori
```

## Mappe eBPF

| Mappa | Tipo | Chiave | Valore |
|---|---|---|---|
| `PDR_MAP` | `HashMap` | TEID (`u32`, host order) | `Pdr { far_id }` |
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action }` |
| `COUNTERS` | `PerCpuArray<u64>` | indice del contatore | contatore |
| `IP_EVENTS` | `RingBuf` (256 KB) | – | `GtpPair { msg_type, teid }` |
| `QER_MAP` | `HashMap` | `qer_id` | `Qer` (definita, non ancora attiva) |

Azioni FAR: `FAR_DROP = 0`, `FAR_FORWARD = 1`; qualsiasi altro valore è trattato come drop.

Il TEID viene convertito da network order a host order nel kernel (`u32::from_be`): le chiavi di
`PDR_MAP` e il campo `teid` di `GtpPair` sono quindi già in host order.

## Regole caricate all'avvio

Definite in `main.rs` e inserite prima dell'attach del programma:

| TEID | PDR → FAR | Azione |
|---|---|---|
| `9999` | `far_id = 1` | `FORWARD` |
| `8888` | `far_id = 2` | `DROP` |

Qualsiasi altro TEID non ha un PDR. In questa fase "nessun PDR" e "nessun FAR" fanno `XDP_PASS`
per non interrompere il traffico durante il debug; in una UPF reale andrebbero scartati.

## Struttura del repository

```
upf_simply/
├── upf_simply/        # loader userspace (Aya, tokio)
├── upf_simply-ebpf/   # programma XDP (no_std)
├── common/            # tipi e costanti condivisi (Pdr, Far, Qer, GtpPair, indici contatori)
├── scripts/test_gtpu.py   # generatore di pacchetti Scapy
└── README.md
```

## Requisiti

- Linux con supporto XDP/eBPF (kernel ≥ 5.8 per `RingBuf`)
- Rust stable + nightly (con `rust-src`)
- `bpf-linker`: `cargo install bpf-linker`
- Privilegi di root (per caricare il programma XDP)
- Python 3 + Scapy per i test: `pip install scapy`

## Build ed esecuzione

Build (programma eBPF + userspace):

```bash
cargo build --release
```

Esecuzione sul loopback (con `sudo -E` per mantenere variabili come `RUST_LOG`):

```bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface lo
```

## Test

In un secondo terminale, dopo aver avviato il loader:

```bash
sudo python3 scripts/test_gtpu.py
```


## Roadmap

- [x] Parsing GTP-U in XDP ed eventi verso lo userspace via `RingBuf`
- [x] Gestione dei PDR e dei FAR tramite mappe eBPF
- [x] Contatori per esito (forward, drop, nessun PDR, nessun FAR)
- [ ] Parsing completo dell'header GTP-U (campi opzionali, PDU Session Container / QFI)
- [ ] Decapsulazione uplink e incapsulazione downlink
- [ ] QER: rate limiting / simulazione QoS (token bucket)
- [ ] Modifica delle regole a runtime (verso un agente PFCP minimale)
- [ ] Test con network namespace e `veth`
- [ ] Test su Raspberry Pi con interfacce reali