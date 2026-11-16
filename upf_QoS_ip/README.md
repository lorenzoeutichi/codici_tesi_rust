# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico, esegue un dispatch rigoroso tra flussi Uplink e Downlink, analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**), ed applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Gli eventi vengono inviati allo userspace in modo **completamente asincrono** tramite `AsyncRingBuf`, mentre le statistiche globali, gli errori specifici e il tracciamento per singolo flusso QoS vengono gestiti tramite mappe per-CPU ad alte prestazioni.

> 🚀 **Stato:** Prototipo Avanzato (Architettura QoS Completa). Il progetto ha raggiunto la maturità del data-path implementando un'architettura **trTCM (Two Rate Three Color Marker)** ibrida e completa. Il programma XDP esegue il policing lock-free (Dual GCRA) e la marcatura dinamica (DSCP), delegando lo shaping fisico e la prioritizzazione al **Linux Traffic Control (TC)** a valle.

## ✨ Funzionalità Attuali

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`) senza puntatori invalidi (stale pointers) attraverso funzioni `adjust_head`.

* **Parsing XDP Sicuro e Gestione Errori Unificata:** Validazione rigorosa della catena Ethernet → IPv4 → UDP → GTP-U v1. Gli errori sono mappati direttamente in contatori specifici tramite l'uso idiomatico di `Result<T, u32>`.

* **Decapsulazione Uplink & Incapsulazione Downlink:** Rimozione e iniezione dinamica di header (inclusi IPv4, UDP, GTP-U ed Extension Headers) con ricalcolo automatico e validazione del checksum IPv4 in uscita.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink) ed emissione dinamica in uscita (Downlink) del container `0x85` per la gestione del **QFI** (QoS Flow Identifier), estrapolato direttamente dal QER.

* **Rate Limiting Avanzato in XDP (trTCM / Dual GCRA Per-CPU):**

  * **Verde (< GBR):** Il traffico rispetta la banda garantita. Passa a priorità normale (TOS inalterato).

  * **Giallo (Tra GBR e MBR):** Il traffico eccede la banda garantita ma non il picco massimo. Il pacchetto passa, ma **XDP altera dinamicamente il campo TOS/DSCP** (`0x38` / AF13) ricalcolando il checksum on-the-fly.

  * **Rosso (> MBR):** Il traffico eccede la banda di picco assoluta. XDP esegue un *hard drop* hardware istantaneo (`XDP_DROP`).

* **Traffic Control (TC) Shaping (HTB & pfifo):** Il control-plane userspace istanzia automaticamente un albero `qdisc` HTB sull'interfaccia di egress. Utilizza filtri `u32` per smistare i pacchetti basandosi sul DSCP impostato da XDP:

  * **Coda Verde (1:10):** Banda garantita pari al GBR.

  * **Coda Gialla (1:20):** Bassa priorità, tetto pari all'MBR, con coda FIFO microscopica per forzare un drop immediato in caso di congestione (Tail Drop fisico).

* **Telemetry Asincrona & Parsing TC:** Invio zero-latenza degli eventi allo userspace tramite `AsyncRingBuf`. Il programma Rust esegue inoltre il parsing periodico dell'output del sottosistema TC per mostrare i drop fisici in tempo reale a terminale.

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
                       │                               │
       PDR_MAP[TEID] ──┤                               ├─ Lookup QER_MAP (QFI)
                       │                               │
       FAR_MAP[far_id] ┴─ DROP/FORWARD                 ├─ FAR Action
                       │                               │
        [ trTCM Rate Limiting (Dual GCRA) ]   [ trTCM Rate Limiting (Dual GCRA) ]
         (Verifica CIR/PIR UL e Drop QoS)      (Verifica CIR/PIR DL e Drop QoS)
                       │                               │
    [ Marcatura TOS/DSCP (Verde/Giallo) ]     [ Marcatura TOS/DSCP (Verde/Giallo) ]
                       │                               │
           [ Decapsulazione (adjust_head) ]        [ Incapsulazione ]
           (Rimozione header tunnel)             (Aggiunta header IP+UDP+GTP+Ext)
                       │                               │
              Invio evento su RingBuf            Calcolo Checksum IPv4
                       │                               │
                   XDP_PASS                        XDP_PASS
                       │                               │
 ══════════════════════▼═══════════════════════════════▼═════════════════════
          [ Linux Traffic Control (TC) - Egress Interface ]
                               │
                          Root HTB (MBR)
                               │
               ┌───────────────┴───────────────┐
       Filtro TOS 0x00                 Filtro TOS 0x38 (AF13)
               │                               │
       [ Coda VERDE (GBR) ]            [ Coda GIALLA (Fino a MBR) ]
       (Coda capiente, no drop)        (FIFO strettissima, drop su congestione)
               │                               │
               └───────────────┬───────────────┘
                               ▼
                        Uscita Fisica

```

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `PDR_MAP` | HashMap | TEID (u32, host order) | `Pdr` { far_id, qer_id... } | Regole Forwarding Uplink | 
| `DL_PDR_MAP` | HashMap | IP UE (u32, host order) | `Pdr` { far_id, qer_id... } | Regole Forwarding Downlink (Routing IP) | 
| `FAR_MAP` | HashMap | far_id (u32) | `Far` { action, ips... } | Definisce l'azione (FORWARD/DROP) e parametri di tunnel | 
| `QER_MAP` | HashMap | qer_id (u32) | `Qer` { qfi, cir_ul, pir_ul...} | QoS Enforcement Rules (Costi temporali calcolati in User Space) | 
| `QER_STATE_MAP` | PerCpuHashMap | qer_id (u32) | `QerState` | Tracciamento TAT Lock-Free (Dual GCRA Per-CPU) | 
| `COUNTERS` | PerCpuArray | Indice globale (u32) | `u64` | Statistiche globali (Forward, Drop, Decap, Encap, Errori) | 
| `QFI_COUNTERS` | PerCpuArray | Valore QFI (u32) | `u64` | Statistiche divise per flussi QoS | 
| `IP_EVENTS` | AsyncRingBuf | – | `GtpPair` | Eventi non-bloccanti verso userspace | 

## 🛠️ Build ed Esecuzione

### 1. Compilazione (Kernel + Userspace)

Assicurati che il tuo `Cargo.toml` workspace sia configurato (e i profili `panic = 'abort'` siano impostati nella root), poi lancia:

```
cargo +nightly xtask build-ebpf
cargo build --release
```

### 2. Creazione Namespace (Topologia di Test)

Esegui lo script di setup (`scripts/setup_netns.sh`) per creare la topologia a namespace (`gnb`, `dn`) e le coppie `veth`.

### 3. Esecuzione del Control Plane (User Space)

Avvia il manager passando i parametri di interfaccia in ingresso, interfaccia di uscita (per agganciare lo shaper TC) e i limiti QoS (MBR e GBR in Mbps).
Il programma installerà il TC sulla corretta interfaccia di *egress*.

**Per testare l'Uplink:**

```
cargo run --release -- --iface-in veth-n3 --iface-out veth-n6 --mbr 100 --gbr 50
```

**Per testare il Downlink:**

```
cargo run --release -- --iface-in veth-n6 --iface-out veth-n3 --mbr 100 --gbr 50

```

### 4. Generazione del Traffico (Testing)

In terminali separati, usa gli script Python con Scapy per innescare le regole di QoS:

**Stress Test Uplink:**

```
sudo ip netns exec gnb python3 scripts/netns_qos_test.py
```

*(Nel terminale principale potrai osservare i drop QoS rossi operati da XDP e, in caso di congestione della classe `1:20`, i drop gialli operati dal kernel Linux HTB).*

**\*\*Test Downlink  e QoS (Encap):\*\***

\`\`\`

sudo ip netns exec dn python3 scripts/netns_encap_test.py

sudo ip netns exec dn python3 scripts/netns_qos_dl_test.py

\`\`\`

*\*(Verifica l'inserimento dell'header tramite: \`sudo ip netns exec gnb tcpdump -i veth-gnb -n -vv -X udp port 2152\`)\**

## 🛣️ Roadmap e Traguardi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace via RingBuf.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU e per-QFI.

* \[x\] Parsing avanzato GTP-U ed estrazione QFI iterativa.

* \[x\] **Decapsulazione Uplink:** Rimozione dinamica dell'header esterno tramite `bpf_xdp_adjust_head` e re-inoltro.

* \[x\] **Incapsulazione Downlink:** Creazione completa stack IPv4/UDP/GTP con ricalcolo checksum.

* \[x\] **Inserimento dinamico del QFI:** Iniezione dell'Extension Header 0x85 in Downlink.

* \[x\] **Rate Limiting QoS (trTCM):** Algoritmo Dual GCRA Per-CPU con *hard drop* per traffico rosso (MBR).

* \[x\] **Marcatura Dinamica (DSCP):** Alterazione *on-the-fly* dell'header IPv4 (TOS `0x38`) per il traffico Giallo.

* \[x\] **Traffic Control (TC) Shaping:** Configurazione dinamica in userspace delle qdisc HTB/PRIO per accodamento e code FIFO restrittive in egress.

* \[ \] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.

* \[ \] Accelerazione XDP_REDIRECT (Bypass stack IP Linux).