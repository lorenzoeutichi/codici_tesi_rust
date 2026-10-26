# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)**.

Un programma **XDP** intercetta il traffico, esegue un dispatch rigoroso tra flussi Uplink e Downlink, analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**), ed applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule) e **FAR** (Forwarding Action Rule) caricate in mappe eBPF. 

Gli eventi vengono inviati allo userspace in modo **completamente asincrono** tramite `AsyncRingBuf`, mentre le statistiche globali, gli errori specifici e il tracciamento per singolo flusso QoS vengono gestiti tramite mappe per-CPU ad alte prestazioni.

> ⚠️ **Stato:** Prototipo Avanzato / Work in Progress. Il progetto vanta ora un'architettura modulare che aggira i limiti del verifier eBPF. La decapsulazione in Uplink è implementata e validata, mentre l'incapsulazione in Downlink è il prossimo step.

## ✨ Funzionalità Attuali

- **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`) senza puntatori invalidi attraverso funzioni `adjust_head`.
- **Parsing XDP Sicuro e Gestione Errori Unificata:** Validazione rigorosa della catena Ethernet → IPv4 → UDP → GTP-U v1. Gli errori (es. pacchetto interno non valido, header troncati) sono mappati direttamente in contatori specifici tramite l'uso idiomatico di `Result<T, u32>`.
- **Decapsulazione Uplink:** Rimozione dinamica dell'header esterno GTP-U/UDP/IPv4 tramite `bpf_xdp_adjust_head`, validazione dell'IP interno (con contatore dedicato `CNT_ERR_INNER_IP`) e re-inoltro.
- **Gestione Extension Headers:** Decodifica iterativa degli header opzionali GTP-U per l'estrazione del **QFI** direttamente dal *PDU Session Container* (Tipo `0x85`).
- **Telemetry Asincrona in Tempo Reale:** Invio zero-latenza degli eventi (Msg Type, TEID, QFI) allo userspace tramite `AsyncRingBuf` (`GtpPair`), integrato nel runtime Tokio senza cicli di polling bloccanti.
- **Control Plane eBPF:** Lookup ultra-veloce nel kernel space tramite `PDR_MAP` e `FAR_MAP`.
- **Statistiche Dettagliate:** Contatori globali e per-CPU (inclusi drop, forward, decap, ed errori) e tracciamento del volume di traffico per ogni singolo valore QFI (0-63).

## 🏗️ Architettura del Flusso

```text
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
       PDR_MAP[TEID] ──┤                               ├─ FAR Action
                       │                               │
       FAR_MAP[far_id] ┴─ DROP/FORWARD                 └─ (WIP: Incapsulazione)
                       │
           [ Decapsulazione (adjust_head) ]
           (Rimozione 36+ byte header ext)
                       │
              Invio evento su RingBuf
                       │
                   XDP_PASS
```

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `PDR_MAP` | `HashMap` | TEID (`u32`, host order) | `Pdr { far_id }` | Regole Forwarding Uplink |
| `DL_PDR_MAP` | `HashMap` | IP UE (`u32`, host order)| `Pdr { far_id }` | Regole Forwarding Downlink (Routing IP) | 
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action }` | Definisce l'azione (es. Drop, Forward) | 
| `QER_MAP` | `HashMap` | `qer_id` (`u32`) | `Qer { qfi, mbr...}` | QoS Enforcement Rules | 
| `COUNTERS` | `PerCpuArray<u64>` | Indice globale (`u32`) | Numero occorrenze | Statistiche globali (Forward, Drop, Decap, Errori) | 
| `QFI_COUNTERS` | `PerCpuArray<u64>` | Valore QFI (`u32`) | Numero occorrenze | Statistiche divise per flussi QoS | 
| `IP_EVENTS` | `AsyncRingBuf` | – | `GtpPair` | Eventi non-bloccanti verso userspace | 

*(Gli indirizzi e il TEID estratti dal pacchetto vengono convertiti tramite `u32::from_be` nel kernel, per cui le chiavi di mappa sono in Host Byte Order).*

## ⚙️ Regole di Test Precaricate

Al momento dell'avvio, il loader userspace inietta le seguenti regole di test nelle mappe eBPF:

| Direzione | Chiave (TEID/IP) | PDR Hit | FAR assegnato | Azione risultante | 
| ----- | ----- | ----- | ----- | ----- | 
| `Uplink` | TEID `9999` | Sì | `1` | `FORWARD` + `DECAP` (Tracciato nei contatori) | 
| `Uplink` | TEID `8888` | Sì | `2` | `DROP` (Tracciato nei contatori) | 
| `Downlink` | IP `10.60.0.1` | Sì | `3` | `FORWARD` (WIP: Incapsulazione verso gNB) | 
| *Qualsiasi* | Altro | No | \- | `PASS` (Fallback di sicurezza) | 


## 🛠️ Build ed Esecuzione

### 1. Compilazione (Kernel + Userspace)

Assicurati che il tuo `Cargo.toml` workspace sia configurato (e i profili `panic = 'abort'` siano impostati nella root), poi lancia:

```bash
cargo +nightly xtask build-ebpf
cargo build --release
```

### 2. Creazione Namespace (Per Test Decap/Encap)

Esegui lo script di setup (scripts/setup_netns.sh) per creare la topologia a namespace (`gnb`, `dn`) e le coppie `veth`.

### 3. Esecuzione

Avvia il manager (user-space) sull'interfaccia collegata alla rete radio (es. `veth-n3`). Utilizzerà automaticamente la modalità *SKB (Generic XDP)*.

```bash
sudo ./target/release/upf_simply --iface veth-n3
```

### 4. Test del traffico Uplink

In un terminale separato, usa lo script Python con Scapy (scripts/netns_decap_test.py) per generare e inviare pacchetti GTP-U verso l'interfaccia in ascolto:

```bash
sudo ip netns exec gnb python3 netns_decap_test.py
```
*Si può osservare l' output asincrono del RingBuffer in tempo reale nel terminale principale e l'avanzamento dei contatori.*

## 🛣️ Roadmap e Prossimi Sviluppi

- [x] Parsing base GTP-U in XDP ed eventi verso userspace.
- [x] Gestione PDR e FAR tramite mappe eBPF.
- [x] Contatori di esito per-CPU.
- [x] Parsing avanzato GTP-U (Ext. Headers, PDU Session Container, estrazione QFI).
- [x] Statistiche basate sui flussi QoS (QFI).
- [x] **Rifattorizzazione Modulare e Ottimizzazione Asincrona (Tokio AsyncRingBuf).**
- [x] **Decapsulazione Uplink:** Rimozione dinamica dell'header esterno tramite `bpf_xdp_adjust_head`, re-inoltro e validazione IP interno (`CNT_ERR_INNER_IP`).
- [ ] **Incapsulazione Downlink (Prossimo Step):** Implementare il percorso inverso (aggiunta dell'header GTP-U, ricalcolo checksum IPv4) per i pacchetti in ingresso destinati alla UE.
- [ ] Inserimento dinamico del QFI nell'header incapsulato in Downlink tramite Lookup QER.
- [ ] Implementazione logiche QER (QoS Enforcement Rule) per il Rate Limiting.
- [ ] Integrazione con un control plane (es. PFCP) per modifiche dinamiche a runtime.
