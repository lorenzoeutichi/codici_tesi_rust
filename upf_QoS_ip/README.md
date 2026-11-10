# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico, esegue un dispatch rigoroso tra flussi Uplink e Downlink, analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**), ed applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Gli eventi vengono inviati allo userspace in modo **completamente asincrono** tramite `AsyncRingBuf`, mentre le statistiche globali, gli errori specifici e il tracciamento per singolo flusso QoS vengono gestiti tramite mappe per-CPU ad alte prestazioni.

> 🚀 **Stato:** Prototipo Avanzato. Il progetto sfrutta un'architettura modulare per superare i limiti del verifier eBPF. Sono pienamente implementate la decapsulazione dinamica (Uplink), l'incapsulazione con inserimento del *PDU Session Container* (Downlink) e l'architettura avanzata di Rate Limiting **trTCM (Two Rate Three Color Marker)**. Il traffico viene ora dinamicamente marcato (DSCP) per lo shaping a valle.

## ✨ Funzionalità Attuali

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`) senza puntatori invalidi (stale pointers) attraverso funzioni `adjust_head`.

* **Parsing XDP Sicuro e Gestione Errori Unificata:** Validazione rigorosa della catena Ethernet → IPv4 → UDP → GTP-U v1. Gli errori sono mappati direttamente in contatori specifici tramite l'uso idiomatico di `Result<T, u32>`.

* **Decapsulazione Uplink & Incapsulazione Downlink:** Rimozione e iniezione dinamica di header (inclusi IPv4, UDP, GTP-U ed Extension Headers) con ricalcolo automatico e validazione del checksum IPv4 in uscita.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink) ed emissione dinamica in uscita (Downlink) del container `0x85` per la gestione del **QFI** (QoS Flow Identifier), estrapolato direttamente dal QER.

* **Rate Limiting Avanzato & Marcatura DSCP (trTCM / Dual GCRA):** Implementazione del Rate Limiting bidirezionale basato su **Two Rate Three Color Marker (trTCM)** e algoritmo **Dual GCRA Per-CPU**:

  * **Verde (< GBR):** Il traffico rispetta la banda garantita. Passa a priorità normale.

  * **Giallo (Tra GBR e MBR):** Il traffico eccede la banda garantita ma non il limite massimo. Il pacchetto passa, ma **XDP altera dinamicamente il campo TOS/DSCP dell'header IPv4 esterno** (es. `AF13`), ricalcolando il checksum. Questo permette al Traffic Control (TC) a valle di instradarlo in code a bassa priorità.

  * **Rosso (> MBR):** Il traffico eccede la banda di picco e viene istantaneamente bloccato (`XDP_DROP`).

* **Telemetry Asincrona in Tempo Reale:** Invio zero-latenza degli eventi (Msg Type, TEID, QFI) allo userspace tramite `AsyncRingBuf` (`GtpPair`), integrato nel runtime Tokio.

* **Control Plane eBPF & Statistiche:** Lookup ultra-veloce nel kernel space tramite `PDR`, `FAR` e `QER` maps. Statistiche globali, per-CPU e per-QFI (0-63).

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
        [ trTCM Rate Limiting (Dual GCRA) ]   [ trTCM Rate Limiting (Dual GCRA) ]
         (Verifica CIR/PIR UL e Drop QoS)      (Verifica CIR/PIR DL e Drop QoS)
                       │                               │
          [ Marcatura TOS/DSCP (Giallo) ]       [ Marcatura TOS/DSCP (Giallo) ]
                       │                               │
           [ Decapsulazione (adjust_head) ]        [ Incapsulazione ]
           (Rimozione 44 byte header ext)        (Aggiunta 44 byte: IP+UDP+GTP+Ext)
                       │                               │
              Invio evento su RingBuf            Calcolo Checksum IPv4
                       │                               │
                   XDP_PASS                        XDP_PASS
                       │
          [ Traffic Control (TC) Shaper ] (HTB/PRIO basato su DSCP)

```

###### 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| PDR_MAP | HashMap | TEID (u32, host order) | Pdr { far_id, qer_id... } | Regole Forwarding Uplink | 
| DL_PDR_MAP | HashMap | IP UE (u32, host order) | Pdr { far_id, qer_id... } | Regole Forwarding Downlink (Routing IP) | 
| FAR_MAP | HashMap | far_id (u32) | Far { action, ips... } | Definisce l'azione e i parametri di tunnel | 
| QER_MAP | HashMap | qer_id (u32) | Qer { qfi, cir_ul, pir_ul...} | QoS Enforcement Rules (Costi temporali ns/byte) | 
| QER_STATE_MAP | PerCpuHashMap | qer_id (u32) | QerState | Tracciamento temporale indipendente (TAT) (Dual GCRA Per-CPU) | 
| COUNTERS | PerCpuArray | Indice globale (u32) | Numero occorrenze | Statistiche globali (Forward, Drop, Decap, Encap, Errori) | 
| QFI_COUNTERS | PerCpuArray | Valore QFI (u32) | Numero occorrenze | Statistiche divise per flussi QoS | 
| IP_EVENTS | AsyncRingBuf | – | GtpPair | Eventi non-bloccanti verso userspace | 

*(Gli indirizzi e il TEID estratti dal pacchetto vengono convertiti tramite `u32::from_be` nel kernel, per cui le chiavi di mappa sono in Host Byte Order).*

###### ⚙️ Regole di Test Precaricate

Al momento dell'avvio, il loader userspace inietta le seguenti regole di test nelle mappe eBPF:

| Direzione | Chiave (TEID/IP) | PDR Hit | FAR assegnato | Azione risultante | 
| ----- | ----- | ----- | ----- | ----- | 
| Uplink | TEID 9999 | Sì | 1 | FORWARD + DECAP (Sottoposto a trTCM Rate Limiting e DSCP marking) | 
| Uplink | TEID 8888 | Sì | 2 | DROP (Tracciato nei contatori) | 
| Downlink | IP 10.60.0.1 | Sì | 3 | FORWARD + ENCAP (Crea Header GTP, inserisce QFI 5, sottoposto a trTCM Rate Limiting e DSCP marking) | 
| *Qualsiasi* | Altro | No | \- | PASS (Fallback di sicurezza) | 

###### 🛠️ Build ed Esecuzione

###### 1. Compilazione (Kernel + Userspace)

Assicurati che il tuo `Cargo.toml` workspace sia configurato (e i profili `panic = 'abort'` siano impostati nella root), poi lancia:

```
cargo +nightly xtask build-ebpf
cargo build --release
```

###### 2. Creazione Namespace (Per Test Decap/Encap)

Esegui lo script di setup (`scripts/setup_netns.sh`) per creare la topologia a namespace (`gnb`, `dn`) e le coppie `veth`.

###### 3. Esecuzione

Avvia il manager (user-space) sull'interfaccia collegata alla rete radio (es. `veth-n3`) o core (`veth-n6`). Utilizzerà automaticamente la modalità *Generic XDP*.

```
cargo run --release -- --iface veth-n3
# In alternativa per il Downlink
RUST_LOG=info cargo run --release -- --iface veth-n6
```

###### 4. Test del traffico Uplink e Downlink

In terminali separati, usa gli script Python con Scapy per testare decapsulazione e incapsulazione.

**Test Uplink (Decap & QoS):**

```
sudo ip netns exec gnb python3 scripts/netns_decap_test.py
```

**Test Downlink  e QoS (Encap):**

```
sudo ip netns exec dn python3 scripts/netns_encap_test.py
sudo ip netns exec dn python3 scripts/netns_qos_dl_test.py
```

*(Verifica l'inserimento dell'header tramite: `sudo ip netns exec gnb tcpdump -i veth-gnb -n -vv -X udp port 2152`)*

###### 🛣️ Roadmap e Prossimi Sviluppi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU.

* \[x\] Parsing avanzato GTP-U (Ext. Headers, PDU Session Container, estrazione QFI).

* \[x\] Statistiche basate sui flussi QoS (QFI).

* \[x\] Rifattorizzazione Modulare e Ottimizzazione Asincrona (Tokio AsyncRingBuf).

* \[x\] Decapsulazione Uplink: Rimozione dinamica dell'header esterno tramite `bpf_xdp_adjust_head`, re-inoltro e validazione IP interno (`CNT_ERR_INNER_IP`).

* \[x\] Incapsulazione Downlink: Implementato il percorso inverso con calcolo del checksum IPv4.

* \[x\] Inserimento dinamico del QFI: Scrittura del *PDU Session Container* nell'header incapsulato tramite Lookup QER.

* \[x\] **Implementazione logiche QER (QoS Enforcement Rule) per il Rate Limiting** tramite architettura trTCM (Dual GCRA Per-CPU).

* \[x\] **Sviluppo avanzato QoS:** Marcatura dinamica del traffico "Giallo" tramite riscrittura campo TOS/DSCP e ricalcolo checksum IPv4.

* \[ \] **Traffic Control (TC) Shaping:** Configurazione delle qdisc Linux (HTB/PRIO) a valle per l'accodamento e la prioritarizzazione dei pacchetti basata sul DSCP.

* \[ \] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.