# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico, esegue un dispatch tra flussi Uplink e Downlink, analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**) ed applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Gli eventi GTP-U vengono inviati allo userspace tramite `RingBuf`, mentre le statistiche globali, gli errori specifici e il tracciamento per singolo flusso QoS vengono gestiti tramite mappe per-CPU.

> 🚀 **Stato:** Prototipo validato funzionalmente in **Uplink e Downlink** su topologia a namespace (veth). L'architettura **trTCM (Two Rate Three Color Marker)** ibrida è completa: il programma XDP esegue il policing lock-free (Dual GCRA) e la marcatura dinamica (DSCP), delegando lo shaping e la prioritizzazione al **Linux Traffic Control (TC)** a valle. La QoS è stata verificata su singolo flusso; il comportamento su più CPU è documentato tra i [limiti noti](#-limiti-noti).

## ✨ Funzionalità Attuali

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`), senza puntatori invalidi (stale pointers) dopo le chiamate a `adjust_head`.

* **Parsing XDP e Gestione Errori Unificata:** Validazione della catena Ethernet → IPv4 → UDP → GTP-U v1. Gli errori sono mappati direttamente in contatori specifici tramite l'uso idiomatico di `Result<T, u32>`.

* **Decapsulazione Uplink & Incapsulazione Downlink:** Rimozione e aggiunta dinamica di header (IPv4, UDP, GTP-U ed Extension Headers) con ricalcolo del checksum IPv4 dell'header esterno. In downlink l'IP interno può essere lungo al massimo **1456 B** (outer = 1500 B): oltre, il pacchetto non viene incapsulato e incrementa il contatore di errore.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink), anche con catene di più extension header, ed emissione in uscita (Downlink) del container `0x85` con il **QFI** (QoS Flow Identifier) letto dalla QER.

* **Rate Limiting in XDP (trTCM / Dual GCRA, stato per-CPU):** per ogni pacchetto si calcola il costo temporale `lunghezza_IP_interno × ns_per_byte` e si aggiornano due TAT (Theoretical Arrival Time), uno per il CIR (GBR) e uno per il PIR (MBR):

  * **Rosso (> MBR):** il nuovo TAT di picco eccede la burst tolerance. XDP esegue `XDP_DROP`, senza aggiornare alcun TAT.

  * **Giallo (tra GBR e MBR):** il traffico eccede il CIR ma non il PIR. Passa, aggiorna solo il TAT di picco, e XDP **marca il TOS/DSCP** (`0x38`, DSCP 14 / AF13) ricalcolando il checksum. In uplink la marcatura è sull'IP interno (prima della decap), in downlink sull'header esterno (in fase di encap).

  * **Verde (< GBR):** rispetta la banda garantita. Aggiorna entrambi i TAT; il TOS non viene modificato.

  La burst tolerance include il costo del pacchetto corrente, quindi deve essere almeno pari al pacchetto più grande: il progetto usa **15000 B** per CIR e PIR.

* **Traffic Control (TC) Shaping (HTB & pfifo):** il control-plane istanzia automaticamente un albero `qdisc` HTB sull'interfaccia di egress, con filtri `u32` sul TOS impostato da XDP:

  * **Root `1:1`:** `rate = ceil = MBR`.

  * **Coda Verde `1:10`:** `rate = GBR`, `ceil = MBR`.

  * **Coda Gialla `1:20`:** `rate` pari all'1% dell'MBR, `ceil = MBR`; è anche la classe di default per i pacchetti con TOS non riconosciuto.

  * Le code foglia sono `pfifo`; il loro limite determina quanti pacchetti vengono scartati dal TC in caso di micro-burst (valori troppo bassi falsano le misure di rate).

* **HTB che misura solo l'IP interno:** il policer XDP conta l'IP interno, mentre l'HTB conta di default tutto il frame (Ethernet e, in DL, anche l'outer header da 44 B). L'opzione `--strip-bytes N` installa sulla qdisc root una size table `stab overhead -N`, così l'HTB e il policer misurano la stessa grandezza. Valori: **14** in uplink (Ethernet), **58** in downlink (Ethernet + IP + UDP + GTP-U + campi opzionali + extension header). Con `--strip-bytes 0` si ottiene l'HTB standard.

* **Telemetria e report:** eventi per ogni pacchetto GTP-U (message type, TEID, QFI) tramite `RingBuf`, letti dallo userspace; ogni 5 secondi il programma stampa i contatori XDP e le statistiche `tc -s class` dell'interfaccia di uscita.

## 🏗️ Architettura del Flusso

```
 Scapy / RAN ──Traffico (GTP/IP)──▶ Interfaccia di Ingresso
                                        │
                    [ Programma XDP - Dispatcher (main.rs) ]
                                Eth → IPv4
                                        │
                       (Protocollo == UDP && Porta == 2152)?
                                 /             \
                               SÌ               NO
                               /                 \
                  [ MODULO UPLINK ]          [ MODULO DOWNLINK ]
            Estrazione iterativa QFI            Lookup IP UE in DL_PDR_MAP
            Evento su RingBuf                          │
                       │                               │
      UL_PDR_MAP[TEID] ┤                               ├─ Lookup QER_MAP (qer_id)
                       │                               │
       FAR_MAP[far_id] ┴─ DROP/FORWARD                 ├─ FAR Action
                       │                               │
        [ trTCM Rate Limiting (Dual GCRA) ]   [ trTCM Rate Limiting (Dual GCRA) ]
         (CIR/PIR UL, Drop QoS se rosso)       (CIR/PIR DL, Drop QoS se rosso)
                       │                               │
    [ Marcatura TOS giallo sull'IP interno ]  [ Incapsulazione ]
                       │                      (IP+UDP+GTP+Ext, TOS giallo
                       │                       sull'header esterno)
           [ Decapsulazione (adjust_head) ]            │
           (Rimozione header tunnel)            Calcolo Checksum IPv4
                       │                               │
                   XDP_PASS                        XDP_PASS
                       │                               │
 ══════════════════════▼═══════════════════════════════▼═════════════════════
          [ Linux Traffic Control (TC) - Egress Interface ]
          (UL: veth-n6 → DN       DL: veth-n3 → gNB)
                               │
                  Root HTB (MBR) + stab overhead -N
                               │
               ┌───────────────┴───────────────┐
       Filtro TOS 0x00                 Filtro TOS 0x38 (AF13)
               │                               │
       [ Coda VERDE (GBR) ]            [ Coda GIALLA (fino a MBR) ]
               │                               │
               └───────────────┬───────────────┘
                               ▼
                        Uscita Fisica
```

L'XDP è attaccato alla sola interfaccia di ingresso (`--iface-in`) e lo shaper alla sola interfaccia di uscita (`--iface-out`): uplink e downlink si provano con **due istanze distinte** a interfacce invertite.

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo |
| ----- | ----- | ----- | ----- | ----- |
| `UL_PDR_MAP` | HashMap | TEID (u32) | `Pdr` { far_id, qer_id, outer_hdr_removed } | Regole di forwarding Uplink |
| `DL_PDR_MAP` | HashMap | IP UE (u32) | `Pdr` { far_id, qer_id } | Regole di forwarding Downlink (routing IP) |
| `FAR_MAP` | HashMap | far_id (u32) | `Far` { action, outer_hdr_creation, peer_ip, peer_teid, local_ip } | Azione (FORWARD/DROP) e parametri di tunnel |
| `QER_MAP` | HashMap | qer_id (u32) | `Qer` { qfi, cir_ul, pir_ul, cir_dl, pir_dl } | Parametri QoS; ogni `BucketParam` ha `ns_per_byte` e `burst_tolerance_ns`, calcolati in userspace |
| `QER_STATE_MAP` | PerCpuHashMap | qer_id (u32) | `QerState` { tat_cir_ul, tat_pir_ul, tat_cir_dl, tat_pir_dl } | Stato dei TAT, lock-free |
| `COUNTERS` | PerCpuArray | indice globale (u32) | `u64` | Forward, decap, encap, drop FAR/QoS, no PDR/FAR/QER/QFI, errori |
| `QFI_COUNTERS` | PerCpuArray | valore QFI (u32) | `u64` | Statistiche per flusso QoS |
| `IP_EVENTS` | RingBuf | – | `GtpPair` | Eventi GTP-U verso userspace |

### Configurazione di test (inserita dal control plane)

| Direzione | Chiave | Regola |
| ----- | ----- | ----- |
| UL | TEID 9999 | FAR 1 (forward, decap), QER 1 |
| UL | TEID 8888 | FAR 2 (drop) |
| DL | UE 10.60.0.1 | FAR 3 (encap verso gNB 10.0.3.2, TEID 7001, sorgente 10.0.3.1), QER 2 |

Topologia: `ns-gnb` (10.0.3.2) ⇄ `veth-gnb`/`veth-n3` ⇄ UPF sull'host ⇄ `veth-n6`/`veth-dn` ⇄ `ns-dn` (10.0.6.2).

## 🛠️ Build ed Esecuzione

### 1. Compilazione (Kernel + Userspace)

Assicurati che il `Cargo.toml` del workspace sia configurato (profili `panic = 'abort'` nella root), poi:

```
cargo +nightly xtask build-ebpf
cargo build --release
```

### 2. Creazione Namespace (Topologia di Test)

Esegui `scripts/setup_netns.sh` per creare i namespace (`ns-gnb`, `ns-dn`) e le coppie `veth`.
### 3. Esecuzione del Control Plane (User Space)

Parametri: interfaccia di ingresso, interfaccia di uscita (dove si installa lo shaper), MBR e GBR in **Mbps**, e `--strip-bytes` (byte non contati dall'HTB). Il GBR deve essere minore dell'MBR (con GBR + 1% MBR ≤ MBR, per il vincolo HTB sulle classi figlie) e con rate oltre ~100 Mbps l'HTB segnala un quantum troppo grande.

**Uplink:**

```
sudo ./target/release/upf_simply --iface-in veth-n3 --iface-out veth-n6 --mbr 20 --gbr 10 --strip-bytes 14
```

**Downlink:**

```
sudo ./target/release/upf_simply --iface-in veth-n6 --iface-out veth-n3 --mbr 20 --gbr 10 --strip-bytes 58
```

Esegui un'istanza alla volta.

### 4. Test automatici (Scapy + tcpdump)

Gli script generano traffico a rate controllato, catturano l'uscita con `tcpdump` e confrontano i risultati con i valori attesi. Il sender va fissato a una CPU con `taskset`, perché lo stato dei TAT è per-CPU.

**Uplink** (dentro `ns-gnb`, cattura in `ns-dn`):

```
sudo taskset -c 2 ip netns exec ns-gnb python3 upf_ul_selftest.py --mbr 20 --gbr 10 \
        --tc-if veth-n6 --green-class 1:10 --yellow-class 1:20 \
        --burst-bytes 15000 --htb-overhead 0
```

**Downlink** (dentro `ns-dn`, cattura in `ns-gnb`):

```
sudo taskset -c 2 ip netns exec ns-dn python3 upf_dl_selftest.py --mbr 20 --gbr 10 \
        --tc-if veth-n3 --green-class 1:10 --yellow-class 1:20 \
        --burst-bytes 15000 --htb-overhead 0
```

Passare `--htb-overhead 0` dice agli script che l'HTB conta solo l'IP interno (cioè che l'istanza UPF è stata avviata con `--strip-bytes`). Senza `--strip-bytes`, ometti l'opzione: gli script usano il valore naturale (14 B in UL, 58 B in DL).

| Fase | Verifica |
| ----- | ----- |
| 1. Funzionale | UL: parsing e decap con flag `0x30`/`0x32`/`0x34` e catena di extension header, TEID in drop e senza PDR.  DL: ogni campo dell'outer header (checksum, lunghezze, TEID, QFI), pacchetto interno identico, limite MTU, UE senza PDR |
| 2. Sweep di rate | Uscita ≈ min(offerto, MBR); quota di verde ≈ min(offerto, GBR) / min(offerto, MBR), letta dal TOS dei pacchetti e dai contatori delle classi HTB |
| 3. Dimensione pacchetto | Con carico oltre l'MBR l'uscita resta ≈ MBR per IP interno da 100, 500, 1000 e 1400 B |
| 4. Burst | Dopo quiete passano circa `burst + MBR × tempo di invio` byte |
| 5. Ricarica | Dopo una pausa un pacchetto passa |

**Come verificare l'inserimento dell'header (manuale):**

```
sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152
```

### Risultati di validazione

Con MBR = 20 Mbps, GBR = 10 Mbps, burst 15000 B e `--strip-bytes` attivo, entrambi gli script chiudono con **0 FAIL** (Uplink: 18 verifiche, Downlink: 17):

* Uscita entro la tolleranza (8%) dell'MBR a saturazione, per ogni dimensione di pacchetto, in entrambe le direzioni.

* Quota di verde 1,00 / 0,67 / 0,56 / 0,50 ai punti di carico offerto 5 e 9 / 15 / 18 / 30 e 60 Mbps, come da formula.

* Il numero di pacchetti verdi per fase coincide con quello atteso dal GBR (6264 su 5 s a 1250 pps più il burst iniziale).

* I conteggi finali dei contatori XDP e delle classi HTB sono coerenti tra loro.

Le misure sono prese su veth con un generatore software e rate fino a 60 Mbps offerti: sono adatte a verificare la correttezza, non le prestazioni.

## ⚠️ Limiti Noti

* **Stato per-CPU.** I TAT stanno in una `PerCpuHashMap`: ogni CPU ha il proprio bucket. Se i pacchetti di una stessa QER vengono distribuiti su più CPU, il rate aggregato può arrivare fino a *N × MBR*. I test sono stati eseguiti con un sender fissato a una CPU, quindi questo comportamento non è ancora misurato. In alternativa, dividere i rate per il numero di CPU limita un singolo flusso a *MBR / N*.

* **Marcatura del verde in uplink.** Il verde non azzera il TOS: un pacchetto interno con TOS diverso da `0x00` e `0x38` finisce nella classe di default (gialla), e uno già a `0x38` risulta giallo anche se conforme.

* **Checksum IPv4 interno (uplink, giallo).** Il ricalcolo assume IHL = 5; il costo del pacchetto viene letto prima di verificare che l'IP interno sia IPv4.

* **Una istanza per direzione.** L'XDP è attaccato a una sola interfaccia, con mappe separate per istanza; UL e DL simultanei in un unico UPF non sono ancora supportati.

* **Solo IPv4, MTU 1500, regole statiche.** Nessun PFCP, nessuna gestione del ciclo di vita delle sessioni; gli UE e i TEID sono inseriti dal control plane all'avvio.

* **Log e eventi nel percorso caldo.** Le macro `info!` e l'evento su `RingBuf` per ogni pacchetto GTP-U alterano le misure di prestazione: vanno rimossi o campionati per i benchmark.

* **Overhead HTB fisso.** `--strip-bytes` sottrae un valore costante per pacchetto: non copre frame con VLAN o encapsulazioni diverse da quella prevista.

## 🛣️ Roadmap e Traguardi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace via RingBuf.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU e per-QFI.

* \[x\] Parsing avanzato GTP-U ed estrazione QFI iterativa.

* \[x\] **Decapsulazione Uplink:** rimozione dell'header esterno tramite `bpf_xdp_adjust_head` e re-inoltro.

* \[x\] **Incapsulazione Downlink:** stack IPv4/UDP/GTP con ricalcolo checksum e controllo MTU.

* \[x\] **Inserimento dinamico del QFI:** Extension Header 0x85 in Downlink.

* \[x\] **Rate Limiting QoS (trTCM):** Dual GCRA con *hard drop* per traffico rosso (MBR), in UL e DL.

* \[x\] **Marcatura Dinamica (DSCP):** TOS `0x38` per il traffico giallo.

* \[x\] **Traffic Control (TC) Shaping:** HTB con classi verde/gialla e filtri sul TOS.

* \[x\] **Allineamento delle unità:** HTB che misura solo l'IP interno (`stab overhead` negativo).

* \[x\] **Test automatici UL e DL** con script Scapy/tcpdump e verifica dei contatori.

* \[ \] Test multi-flusso e multi-CPU (comportamento aggregato del bucket per-CPU).

* \[ \] UL e DL contemporanei in un'unica istanza, con più QER in parallelo.

* \[ \] Corpus di pacchetti malformati (GTP troncato, lunghezze incoerenti, message type diversi da 255, IPv6, opzioni IP).

* \[ \] Ripetizione dei test e riferimento indipendente del GCRA (modello in Python sullo stesso flusso).

* \[ \] Benchmark con TRex (pps, latenza, NIC reale).

* \[ \] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.

* \[ \] Accelerazione XDP_REDIRECT (bypass dello stack IP Linux).
