# upf_PDR/FAR_QFI (Prototipo UPF 5G in eBPF/Rust)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico GTP-U, ne analizza gli header (inclusi gli Extension Headers per ricavare il **QFI**), estrae il `TEID` e applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule) e **FAR** (Forwarding Action Rule) caricate in mappe eBPF.
Gli eventi vengono inviati allo userspace tramite **RingBuf**, mentre le statistiche globali e per singolo flusso QoS vengono tracciate tramite mappe per-CPU ad alte prestazioni.

> ⚠️ **Stato:** Prototipo / Work in Progress. Attualmente implementa il parsing e le regole di filtraggio/inoltro, in preparazione per l'effettiva manipolazione dei pacchetti (decapsulazione/incapsulazione).

## ✨ Funzionalità Attuali

* **Parsing XDP Sicuro:** Validazione catena Ethernet → IPv4 → UDP (porta `2152`) → GTP-U v1.

* **Gestione Extension Headers:** Decodifica iterativa degli header opzionali GTP-U per l'estrazione del **QFI** (QoS Flow Identifier) direttamente dal *PDU Session Container* (Tipo `0x85`).

* **Telemetry in Tempo Reale:** Invio asincrono degli eventi (Msg Type, TEID, QFI) allo userspace tramite `RingBuf` (`GtpPair`).

* **Control Plane eBPF:** Lookup ultra-veloce nel kernel space tramite:

  * **Tabella PDR** (`PDR_MAP`, chiave: TEID).

  * **Tabella FAR** (`FAR_MAP`, chiave: FAR_ID) per le azioni di `FORWARD` (`XDP_PASS`) o `DROP` (`XDP_DROP`).

* **Statistiche Dettagliate:**

  * Contatori globali (`PerCpuArray`): Pacchetti inoltrati, droppati, o privi di PDR/FAR.

  * Contatori QoS (`QFI_COUNTERS`): Tracciamento del volume di traffico per ogni singolo valore QFI (0-63).

* **Userspace Manager:** Un loader scritto in Tokio che popola le mappe all'avvio, consuma il RingBuf e stampa report periodici dei contatori. 

## 🏗️ Architettura del Flusso

```
 Scapy / Simulatore ──GTP-U (UDP 2152)──▶ Interfaccia di rete (es. lo)
                                                │
                                        [ Programma XDP ]  (Kernel Space)
                                Eth → IPv4 → UDP:2152 → GTP-U (+ Ext Headers)
                                                │
                                msg_type = 255 (G-PDU)?  ── no ──▶ XDP_PASS
                                                │ sì
                                 Estrazione iterativa QFI
                                                │
                           PDR_MAP[TEID] ── assente ──▶ Contatore "no PDR", XDP_PASS
                                                │
                         FAR_MAP[far_id] ── assente ──▶ Contatore "no FAR", XDP_PASS
                                                │
                                       Azione definita dal FAR
                           ┌──────────────────────┴──────────────────────┐
                        FORWARD                                 DROP / altro
                    Contatore forward                       Contatore drop (FAR)
                       XDP_PASS                                   XDP_DROP

              (Per ogni GTP-U valido) 
              Generazione GtpPair { msg_type, qfi, teid }
                                                │
                                           [ RingBuf ]
                                                │
                                   [ Userspace Loader / Manager ]  (Tokio)
                     Popola PDR/FAR, legge eventi, stampa report contatori

```

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `PDR_MAP` | `HashMap` | TEID (`u32`, host order) | `Pdr { far_id }` | Associa un Tunnel a una regola di Forwarding | 
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action }` | Definisce l'azione (0 = Drop, 1 = Forward) | 
| `COUNTERS` | `PerCpuArray<u64>` | Indice globale (`u32`) | Numero occorrenze | Statistiche globali lock-free | 
| `QFI_COUNTERS` | `PerCpuArray<u64>` | Valore QFI (`u32`) | Numero occorrenze | Statistiche divise per flussi QoS | 
| `IP_EVENTS` | `RingBuf` (256 KB) | – | `GtpPair` | Coda circolare per gli eventi verso lo userspace | 

*(Il TEID estratto dal pacchetto viene convertito tramite `u32::from_be` nel kernel, per cui le chiavi di `PDR_MAP` sono memorizzate in Host Byte Order).*

## ⚙️ Regole di Test Precaricate

Al momento dell'avvio, il loader userspace inietta le seguenti regole di test nelle mappe eBPF:

| TEID in ingresso | PDR Hit | FAR assegnato | Azione risultante | 
| ----- | ----- | ----- | ----- | 
| `9999` | Sì | `1` | `FORWARD` (Tracciato nei contatori) | 
| `8888` | Sì | `2` | `DROP` (Tracciato nei contatori) | 
| *Qualsiasi altro* | No | \- | `PASS` (Fallback di sicurezza) | 

## 🚀 Requisiti e Setup (Ambiente WSL 2 / Ubuntu)

Per compilare ed eseguire il progetto su Windows Subsystem for Linux (WSL), assicurati di avere i seguenti strumenti installati:

1. **Toolchain Rust:**

   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup default stable
   rustup toolchain install nightly --component rust-src
   cargo install bpf-linker
   
   ```

2. **Dipendenze di Sistema per eBPF/XDP:**

   ```
   sudo apt-get update
   sudo apt-get install -y clang llvm libbpf-dev libc6-dev xdp-tools libxdp-dev linux-headers-generic linux-tools-common
   
   ```

3. **Scapy (per i test):**

   ```
   sudo apt-get install -y python3-scapy
   
   ```

*(Nota: Su WSL il file system BPF potrebbe non essere montato di default. Se ricevi errori sulle mappe all'avvio, esegui: `sudo mount -t bpf bpf /sys/fs/bpf/`)*.

## 🛠️ Build ed Esecuzione

### 1. Compilazione (Kernel + Userspace)

Assicurati che il tuo `Cargo.toml` workspace sia configurato correttamente, poi lancia:

```
cargo build --release

```

### 2. Esecuzione

Avvia il manager sulla tua interfaccia di loopback (`lo`). Si utilizzerà automaticamente la modalità *SKB (Generic XDP)*, che è compatibile con le limitazioni dei driver virtuali di WSL.

```
cargo run --release -- --iface lo

```

### 3. Test del traffico

In un terminale separato, usa lo script Python con Scapy per generare e inviare pacchetti GTP-U verso l'interfaccia in ascolto:

```
sudo python3 scripts/test_gtp_qfi.py

```

*(Dovresti vedere l'output del parsing nel terminale principale e l'avanzamento dei contatori ogni 5 secondi).*

## 🛣️ Roadmap e Prossimi Sviluppi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace via `RingBuf`.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU.

* \[x\] Parsing avanzato GTP-U (Ext. Headers, PDU Session Container, estrazione QFI).

* \[x\] Statistiche basate sui flussi QoS (QFI).

* \[ \] **Decapsulazione e Incapsulazione GTP-U (Prossimo Step):**

  * **Uplink:** Implementare la rimozione dinamica dell'header esterno tramite `bpf_xdp_adjust_head`, re-inoltrando il pacchetto IP interno.

  * **Downlink:** Implementare il percorso inverso (aggiunta dell'header GTP-U) per i pacchetti in ingresso destinati alla UE.

* \[ \] Implementazione logiche QER (QoS Enforcement Rule) per il Rate Limiting.

* \[ \] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.

* \[ \] Test su Raspberry Pi con interfacce reali