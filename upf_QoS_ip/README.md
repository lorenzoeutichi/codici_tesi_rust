# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico, esegue un dispatch rigoroso tra flussi Uplink e Downlink, analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**), ed applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Gli eventi vengono inviati allo userspace in modo **completamente asincrono** tramite `AsyncRingBuf`, mentre le statistiche globali, gli errori specifici e il tracciamento per singolo flusso QoS vengono gestiti tramite mappe per-CPU ad alte prestazioni.

> 🚀 **Stato:** Prototipo Avanzato. Il progetto sfrutta un'architettura modulare per superare i limiti del verifier eBPF. Sono ora pienamente implementate e validate sia la decapsulazione dinamica in Uplink, sia l'incapsulazione in Downlink con l'inserimento dinamico del *PDU Session Container* (QFI).

## ✨ Funzionalità Attuali

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`) senza puntatori invalidi (stale pointers) attraverso funzioni `adjust_head`.

* **Parsing XDP Sicuro e Gestione Errori Unificata:** Validazione rigorosa della catena Ethernet → IPv4 → UDP → GTP-U v1. Gli errori (es. pacchetto interno non valido, header troncati, MTU superato) sono mappati direttamente in contatori specifici tramite l'uso idiomatico di `Result<T, u32>`.

* **Decapsulazione Uplink:** Rimozione dinamica dell'header esterno GTP-U/UDP/IPv4 tramite `bpf_xdp_adjust_head`, validazione dell'IP interno (con contatore dedicato `CNT_ERR_INNER_IP`) e re-inoltro.

* **Incapsulazione Downlink (Encap + QFI):** Iniezione di 44 byte in testa al pacchetto IP tramite `adjust_head` negativo. Generazione da zero degli header IPv4 (con ricalcolo automatico del checksum), UDP, GTP-U e inserimento dell'Extension Header (PDU Session Container) estrando il QFI dalle mappe.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink) ed emissione dinamica in uscita (Downlink) del container `0x85` per la gestione del **QFI** (QoS Flow Identifier), estrapolato direttamente dal QER.

* **Telemetry Asincrona in Tempo Reale:** Invio zero-latenza degli eventi (Msg Type, TEID, QFI) allo userspace tramite `AsyncRingBuf` (`GtpPair`), integrato nel runtime Tokio senza cicli di polling bloccanti.

* **Control Plane eBPF:** Lookup ultra-veloce nel kernel space tramite `PDR_MAP`, `DL_PDR_MAP`, `FAR_MAP` e `QER_MAP`.

* **Statistiche Dettagliate:** Contatori globali e per-CPU (inclusi drop, forward, decap, encap ed errori) e tracciamento del volume di traffico per ogni singolo valore QFI (0-63).

## 🏗️ Architettura del Flusso

```
 Scapy / RAN ──Traffico (GTP/IP)──▶ Interfaccia di rete (es. veth)
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
           [ Decapsulazione (adjust_head) ]        [ Incapsulazione ]
           (Rimozione 36+ byte header ext)       (Aggiunta 44 byte: IP+UDP+GTP+Ext)
                       │                               │
              Invio evento su RingBuf            Calcolo Checksum IPv4
                       │                               │
                   XDP_PASS                        XDP_PASS

```

#### 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `PDR_MAP` | `HashMap` | TEID (`u32`, host order) | `Pdr { far_id, qer_id... }` | Regole Forwarding Uplink | 
| `DL_PDR_MAP` | `HashMap` | IP UE (`u32`, host order) | `Pdr { far_id, qer_id... }` | Regole Forwarding Downlink (Routing IP) | 
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action, ips... }` | Definisce l'azione e i parametri di tunnel | 
| `QER_MAP` | `HashMap` | `qer_id` (`u32`) | `Qer { qfi, mbr...}` | QoS Enforcement Rules (QFI mapping) | 
| `COUNTERS` | `PerCpuArray<u64>` | Indice globale (`u32`) | Numero occorrenze | Statistiche globali (Forward, Drop, Decap, Encap, Errori) | 
| `QFI_COUNTERS` | `PerCpuArray<u64>` | Valore QFI (`u32`) | Numero occorrenze | Statistiche divise per flussi QoS | 
| `IP_EVENTS` | `AsyncRingBuf` | – | `GtpPair` | Eventi non-bloccanti verso userspace | 

*(Gli indirizzi e il TEID estratti dal pacchetto vengono convertiti tramite `u32::from_be` nel kernel, per cui le chiavi di mappa sono in Host Byte Order).*

#### ⚙️ Regole di Test Precaricate

Al momento dell'avvio, il loader userspace inietta le seguenti regole di test nelle mappe eBPF:

| Direzione | Chiave (TEID/IP) | PDR Hit | FAR assegnato | Azione risultante | 
| ----- | ----- | ----- | ----- | ----- | 
| Uplink | TEID 9999 | Sì | 1 | `FORWARD` + `DECAP` (Tracciato nei contatori) | 
| Uplink | TEID 8888 | Sì | 2 | `DROP` (Tracciato nei contatori) | 
| Downlink | IP 10.60.0.1 | Sì | 3 | `FORWARD` + `ENCAP` (Crea Header GTP con TEID 7001 e inserisce QFI 5) | 
| *Qualsiasi* | Altro | No | \- | `PASS` (Fallback di sicurezza) | 

#### 🛠️ Build ed Esecuzione

##### 1. Compilazione (Kernel + Userspace)

Assicurati che il tuo `Cargo.toml` workspace sia configurato (e i profili `panic = 'abort'` siano impostati nella root), poi lancia:

```
cargo +nightly xtask build-ebpf
cargo build --release

```

##### 2. Creazione Namespace (Per Test Decap/Encap)

Esegui lo script di setup (`scripts/setup_netns.sh`) per creare la topologia a namespace (`gnb`, `dn`) e le coppie veth. È necessario abilitare `accept_local=1` sull'interfaccia `veth-n6` per instradare i pacchetti con IP sorgente manipolato da XDP.

##### 3. Esecuzione

Avvia il manager (user-space) sull'interfaccia collegata alla rete radio (es. `veth-n3`) o core (`veth-n6`). Utilizzerà automaticamente la modalità *SKB (Generic XDP)*.

```
cargo run --release -- --iface veth-n3

RUST_LOG=info cargo run --release -- --iface veth-n6
```

##### 4. Test del traffico Uplink e Downlink

In terminali separati, usa gli script Python con Scapy per testare decapsulazione e incapsulazione, intercettando l'esito tramite tcpdump.

**Test Uplink (Decap):**

```
sudo ip netns exec gnb python3 scripts/netns_decap_test.py

```

**Test Downlink (Encap):**

```
sudo ip netns exec dn python3 scripts/netns_encap_test.py

```

*(Verifica l'inserimento dell'header tramite: `sudo ip netns exec gnb tcpdump -i veth-gnb -n -vv -X udp port 2152`)*

#### 🛣️ Roadmap e Prossimi Sviluppi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU.

* \[x\] Parsing avanzato GTP-U (Ext. Headers, PDU Session Container, estrazione QFI).

* \[x\] Statistiche basate sui flussi QoS (QFI).

* \[x\] **Rifattorizzazione Modulare e Ottimizzazione Asincrona (Tokio AsyncRingBuf).**

* \[x\] **Decapsulazione Uplink:** Rimozione dinamica dell'header esterno tramite `bpf_xdp_adjust_head`, re-inoltro e validazione IP interno (`CNT_ERR_INNER_IP`).

* \[x\] **Incapsulazione Downlink:** Implementato il percorso inverso con calcolo del checksum IPv4.

* \[x\] **Inserimento dinamico del QFI:** Scrittura del *PDU Session Container* nell'header incapsulato tramite Lookup QER in Downlink.

* \[ \] Implementazione logiche QER (QoS Enforcement Rule) per il Rate Limiting.

* \[ \] (Opzionale) Implementazione instradamento accelerato bypassando lo stack di rete tramite `XDP_REDIRECT` e `bpf_fib_lookup`.

* \[ \] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.