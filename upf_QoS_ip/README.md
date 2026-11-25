# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane e control plane leggero per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)** e **Tokio**.

Un singolo programma **XDP** agganciato simultaneamente alle interfacce **RAN** (N3) e **Data Network** (N6) intercetta il traffico in modalità **Full-Duplex**, esegue il dispatch tra flussi Uplink e Downlink in base all'interfaccia di ingresso (`ingress_ifindex`), analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**) e applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Lo userspace espone un **Control Plane asincrono su UDP/JSON** (porta standard PFCP `8805`) che opera secondo il principio dell'interfaccia 3GPP N4 (**TS 29.244 §8.2.27**): valida le policy 5QI/QFI, risolve la mappatura **5QI** $\rightarrow$ **DSCP** (allineata a **3GPP TS 23.501**, **IETF RFC 4594/2597/3246/2698** e **GSMA PRD IR.34**) e aggiorna le mappe eBPF a runtime senza interrompere il data plane.

> 🚀 **Stato:** Prototipo **Full-Duplex multi-classe** validato funzionalmente (0 FAIL su tutte le suite UL, DL e Control Plane live) su singola istanza UPF in topologia a namespace (`veth`). L'architettura ibrida **XDP + Linux TC** integra policing **trTCM (Dual GCRA)** lock-free, gestione dedicata dei flussi **Non-GBR / Non-QoS**, marcatura attiva **DSCP con anti-spoofing e preservazione ECN**, e doppio shaper **HTB + `fq_codel`** a **4 classi di servizio** (7 code foglia) con isolamento del traffico Best-Effort. La QoS è stata verificata su singolo core per direzione; il comportamento multi-CPU è documentato tra i [limiti noti](#️-limiti-noti).

## ✨ Funzionalità Attuali

* **UPF Full-Duplex (Singola Istanza N3 + N6):** Un unico programma XDP viene caricato una sola volta e agganciato contemporaneamente alle interfacce `--iface-ran` (RAN) e `--iface-dn` (DN). Il dispatch identifica la sorgente leggendo `ingress_ifindex` e consultando `IFACE_ROLE_MAP` (`IFACE_ROLE_RAN` / `IFACE_ROLE_DN`), in aderenza al concetto 3GPP di *Source Interface*.

* **Control Plane Dinamico Asincrono (Mini-PFCP su UDP/JSON):** Il modulo `control.rs` esegue un listener Tokio `UdpSocket` (default `127.0.0.1:8805`) che condivide in sicurezza le mappe eBPF tramite `ControlState` (`Arc<Mutex<...>>` con ownership acquisita via `take_map`). Supporta inserimento, aggiornamento QoS live (senza azzerare i TAT dei flussi attivi), declassamento a Non-QoS (`0/0`) e rimozione delle sessioni tramite comandi JSON, rispondendo con esiti strutturati `{"ok": bool, "message": "..."}`. Le scritture seguono l'ordine sicuro `QER_STATE -> QER -> FAR -> PDR` (inverso in cancellazione) per garantire consistenza con i lettori lock-free in XDP.

* **Mappatura Multi-Classe 5QI** $\rightarrow$ **DSCP (3GPP / IETF / GSMA):** Coerentemente con **3GPP TS 29.244 §8.2.27**, il kernel XDP non contiene tabelle di mappatura né esegue lookup aggiuntivi: il Control Plane traduce il `5qi` nella coppia `(dscp_green, dscp_yellow)` e la memorizza direttamente nella `Qer` (mantenendo `qfi` indipendente e validato nel range a 6 bit `0–63`).

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`), privo di puntatori invalidi (*stale pointers*) dopo le chiamate a `bpf_xdp_adjust_head`.

* **Parsing XDP e Gestione Errori Unificata per Direzione:** Validazione della catena Ethernet $\rightarrow$ IPv4 $\rightarrow$ UDP $\rightarrow$ GTP-U v1. Gli errori sono mappati tramite `Result<T, u32>` e instradati automaticamente dall'entrypoint XDP nella mappa contatori della direzione corretta (`COUNTERS_UL` o `COUNTERS_DL`).

* **Decapsulazione Uplink & Incapsulazione Downlink:** Rimozione e aggiunta dinamica di header (IPv4, UDP, GTP-U ed Extension Headers) con ricalcolo del checksum IPv4. In downlink l'IP interno può essere lungo al massimo **1456 B** (outer = 1500 B): oltre tale soglia il pacchetto non viene incapsulato e incrementa `CNT_ERR` in `COUNTERS_DL`.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink), anche con catene di più extension header, ed emissione in uscita (Downlink) del container `0x85` (*PDU Session Container*) con il **QFI** a 6 bit (`qfi & 0x3F`) letto dalla QER.

* **Rate Limiting in XDP (trTCM / Dual GCRA per-CPU) & Gestione Non-GBR:** Per i flussi GBR, XDP calcola il costo temporale `ip_tot_length * ns_per_byte` (in aritmetica a virgola fissa Q30) e aggiorna due TAT (*Theoretical Arrival Time*) per il CIR (GBR) e il PIR (MBR):

  * **Rosso (**$> \text{MBR}$**):** Il nuovo TAT di picco eccede la burst tolerance. XDP esegue `XDP_DROP` senza aggiornare alcun TAT.

  * **Giallo (**$\text{GBR} < \text{rate} \le \text{MBR}$**):** Eccede il CIR ma non il PIR. Aggiorna solo il TAT di picco e applica `qer.dscp_yellow` (Drop Precedence 3 secondo **RFC 2597**, es. `AF43` o `AF33`). Per i profili `EF` (**RFC 3246**) vige policing stretto con $\text{GBR} = \text{MBR}$ (nessun declassamento giallo).

  * **Verde (**$\le \text{GBR}$**):** Rispetta la banda garantita. Aggiorna entrambi i TAT e applica `qer.dscp_green`.

  * **Non-GBR / Non-QoS (`qer_id == 0` oppure `pir == 0`):** Bypassa il Dual GCRA, incrementa `CNT_NON_QOS` e applica il codepoint previsto (`qer.dscp_green` per i 5QI Non-GBR come `CS5` o `AF11`, `DSCP_BE = 0` per `5QI = 9` o sessioni `qos: null`).

* **Marcatura Attiva DSCP, Anti-Spoofing e Preservazione ECN:** XDP riscrive attivamente i 6 bit DSCP per **tutti** i pacchetti inoltrati (Verdi, Gialli e Non-QoS), impedendo ai terminali di falsificare la priorità del traffico (anti-spoofing). In Uplink (`mark_dscp_checksum_ipv4hdr`) vengono preservati i 2 bit **ECN** originali dell'IP interno e il ricalcolo del checksum viene saltato se il DSCP coincide già; in Downlink (`encap_dl`) il DSCP viene scritto sull'header IPv4 esterno ignorando il TOS del pacchetto interno.

* **Traffic Control (TC) Shaping Multi-Classe Bidirezionale (HTB & `fq_codel`):** Il loader configura automaticamente su entrambe le interfacce di egress (`iface_dn` per l'Uplink, `iface_ran` per il Downlink) un albero HTB a **4 classi GSMA IR.34** (7 code foglia `fq_codel`) con filtri `u32` a maschera **`0xfc`** (match sui soli 6 bit DSCP, ECN-safe) e isolamento rigido tra traffico QoS (`1:1`) e traffico Non-GBR/Best-Effort (`1:40`).

* **Allineamento delle Unità HTB (`--strip-bytes-ul` / `--strip-bytes-dl`):** Il policer XDP misura l'IP interno, mentre l'HTB conta di default l'intero frame. Le opzioni `--strip-bytes-ul` (default **14 B**: Ethernet su N6) e `--strip-bytes-dl` (default **58 B**: Ethernet + 44 B di outer IP/UDP/GTP-U/Ext su N3) installano una size table `stab overhead -N` sulle qdisc root, allineando al singolo byte le misure tra XDP e TC. Impostando `0` si ottiene l'HTB standard.

* **Telemetria Separata e Report Tabellare:** Eventi GTP-U (`GtpPair`) tramite `RingBuf`; ogni 5 secondi e alla chiusura (`Ctrl+C`), lo userspace stampa una tabella affiancata (`Uplink | Downlink | Totale`) per i contatori XDP (incluso `pkts Non-QoS`) e per ogni QFI attivo, seguita ogni 30 secondi e in chiusura dalle statistiche `tc -s class` di entrambe le interfacce di uscita.

## 🎯 Mappatura 5QI $\rightarrow$ DSCP $\rightarrow$ Classi TC

La tabella seguente combina **3GPP TS 23.501** (profili 5QI), **IETF RFC 4594 / 3246 / 2597 / 2698** (classi DiffServ, EF, Drop Precedence AF e trTCM) e **GSMA PRD IR.34** (aggregazione in 4 classi di trasporto):

| 5QI (TS 23.501) | Servizio tipico e Risorsa | Classe DiffServ | DSCP Verde (TOS) | DSCP Giallo (TOS) | Foglia HTB (`prio`) | Comportamento in XDP | 
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | 
| `82–85`, `1`, `3`, `65` | URLLC, VoNR, Real-Time Gaming, MC Voice (*GBR / DC-GBR*) | Expedited Forwarding (`EF`) | `EF` / `46` (`0xB8`) | — *(strict)* | `1:10` (`prio 0`) | $\text{GBR} = \text{MBR}$ obbligatorio: conforme $\rightarrow$ `EF`, eccedente $\rightarrow$ `XDP_DROP` | 
| `5`, `69` | IMS / Mission-Critical Signalling (*Non-GBR*) | Signalling (`CS5`) | `CS5` / `40` (`0xA0`) | — *(Non-GBR)* | `1:10` (`prio 0`) | Bypass trTCM (`pir == 0`), marcatura statica `CS5` | 
| `2`, `67` | Conversational / MC Video (*GBR*) | Multimedia Conf. (`AF4x`) | `AF41` / `34` (`0x88`) | `AF43` / `38` (`0x98`) | `1:21` (`prio 1`) / `1:22` (`prio 2`) | trTCM 3 colori: Verde `AF41`, Giallo `AF43`, Rosso `XDP_DROP` | 
| `4`, `66` | Buffered Video / MC Data (*GBR*) | Multimedia Stream. (`AF3x`) | `AF31` / `26` (`0x68`) | `AF33` / `30` (`0x78`) | `1:31` (`prio 3`) / `1:32` (`prio 4`) | trTCM 3 colori: Verde `AF31`, Giallo `AF33`, Rosso `XDP_DROP` | 
| `6`, `7`, `8` | Video TCP / Interactive (*Non-GBR*) | Interactive (`AF11`) | `AF11` / `10` (`0x28`) | — *(Non-GBR)* | `1:41` (`prio 5`) | Bypass trTCM (`pir == 0`), shaper isolato `1:40` | 
| `9` *(o `qos: null`)* | Default Internet / Best-Effort (*Non-GBR*) | Default (`CS0`) | `CS0` / `0` (`0x00`) | — *(Non-GBR)* | `1:42` (`prio 6`, `default 42`) | Bypass trTCM, shaper isolato `1:40` (`fq_codel limit 200`) | 

### FQ-CoDel come Leaf Qdisc

Tutte e 7 le classi foglia HTB impiegano **`fq_codel`** (*Fair Queueing Controlled Delay*) per contenere il bufferbloat tramite Active Queue Management (AQM) e garantire equità tra i micro-flussi IP incapsulati nello stesso tunnel GTP-U. Sulla foglia Best-Effort `1:42` è impostato `limit 200` per evitare code eccessive sotto saturazione prolungata e garantire tempi di svuotamento rapidi.

## 🏗️ Architettura del Flusso

```
                            [ Control Plane UDP/JSON ]
                         Tokio UdpSocket (127.0.0.1:8805)
                 5QI -> (dscp_green, dscp_yellow) + Validazione Policy
                     add / update_qer / delete -> Arc<Mutex<Maps>>
                                        │
                    (aggiornamento runtime mappe PDR/FAR/QER)
                                        ▼
 gNB (N3) ──GTP-U/IP──▶ iface-ran ──┐          ┌── iface-dn ◀──IP UE── DN (N6)
                                    ▼          ▼
                    [ Programma XDP Unico (main.rs) ]
                      Lookup ingress_ifindex in IFACE_ROLE_MAP
                                  Eth -> IPv4
                                  /          \
                       (IFACE_ROLE_RAN)   (IFACE_ROLE_DN)
                              /                  \
                   UDP dport == 2152?             │
                       SÌ │  NO -> PASS           │
                          ▼                       ▼
                  [ MODULO UPLINK ]      [ MODULO DOWNLINK ]
            Estrazione iterativa QFI       Lookup IP UE in DL_PDR_MAP
            Evento su RingBuf                     │
                       │                          ├─ Lookup QER_MAP (QFI)
      UL_PDR_MAP[TEID] ┤                          ├─ FAR Action (DROP/FWD)
       FAR_MAP[far_id] ┴─ DROP/FWD                │
                       │                          │
        [ Policing UL (Dual GCRA) ]      [ Policing DL (Dual GCRA) ]
         GBR -> Green/Yellow/Red          GBR -> Green/Yellow/Red
         Non-GBR / No-QER -> Bypass       Non-GBR / No-QER -> Bypass
                       │                          │
      [ Marcatura DSCP su IP int ]       [ Incapsulazione 44 B + QFI 0x85 ]
       (anti-spoofing, ECN intatto)      (DSCP su IP ext + Checksum IPv4)
                       │                          │
           [ Decapsulazione ]                     │
         (adjust_head positivo)                   │
                       │                          │
               COUNTERS_UL / QFI_UL       COUNTERS_DL / QFI_DL
                   XDP_PASS                   XDP_PASS
                       │                          │
 ══════════════════════▼══════════════════════════▼═════════════════════════
        [ TC Egress UL: veth-n6 ]        [ TC Egress DL: veth-n3 ]
      HTB default 42 + stab -14 B      HTB default 42 + stab -58 B
       (filtri u32 con maschera 0xfc su entrambe le interfacce)
                       │
         ┌─────────────┴───────────────────────────────────┐
         ▼                                                 ▼
   [ Root QoS 1:1 (link_rate) ]                [ Root Non-QoS 1:40 (non_qos_rate) ]
    ├── 1:10 (prio 0, ef_rate)    EF 0xB8 / CS5 0xA0     ├── 1:41 (prio 5)  AF11 0x28
    ├── 1:20 (mbr)                                       └── 1:42 (prio 6)  CS0  0x00
    │    ├── 1:21 (prio 1, gbr)   AF41 0x88                  (fq_codel limit 200)
    │    └── 1:22 (prio 2, 1%)    AF43 0x98
    └── 1:30 (mbr)
         ├── 1:31 (prio 3, gbr)   AF31 0x68
         └── 1:32 (prio 4, 1%)    AF33 0x78
         │                                                 │
         ▼                                                 ▼
     DN (ns-dn) / gNB (ns-gnb)                 DN (ns-dn) / gNB (ns-gnb)

```

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `IFACE_ROLE_MAP` | `HashMap` | `ifindex` (`u32`) | Ruolo (`u8`: `RAN` / `DN`) | Dispatch Full-Duplex basato sull'interfaccia di ingresso | 
| `UL_PDR_MAP` | `HashMap` | TEID (`u32`) | `Pdr { far_id, qer_id, outer_hdr_removed }` | Regole di forwarding Uplink | 
| `DL_PDR_MAP` | `HashMap` | IP UE (`u32`) | `Pdr { far_id, qer_id, outer_hdr_removed }` | Regole di forwarding Downlink (routing IP) | 
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action, outer_hdr_creation, peer_ip, peer_teid, local_ip }` | Azione (`FORWARD`/`DROP`) e parametri del tunnel | 
| `QER_MAP` | `HashMap` | `qer_id` (`u32`) | `Qer { qfi, five_qi, dscp_green, dscp_yellow, cir_ul, pir_ul, cir_dl, pir_dl }` | Profilo 5QI/DSCP e parametri QoS (`ns_per_byte` Q30 e `burst_tolerance_ns`) | 
| `QER_STATE_MAP` | `PerCpuHashMap` | `qer_id` (`u32`) | `QerState { tat_cir_ul, tat_pir_ul, tat_cir_dl, tat_pir_dl }` | Stato dei TAT del Dual GCRA, lock-free | 
| `COUNTERS_UL` | `PerCpuArray` | indice (`u32`) | `u64` | Statistiche ed errori del ramo Uplink (incluso `CNT_NON_QOS`) | 
| `COUNTERS_DL` | `PerCpuArray` | indice (`u32`) | `u64` | Statistiche ed errori del ramo Downlink (incluso `CNT_NON_QOS`) | 
| `QFI_COUNTERS_UL` | `PerCpuArray` | valore QFI (`u32`) | `u64` | Conteggio pacchetti per QFI (`0–63`) in Uplink | 
| `QFI_COUNTERS_DL` | `PerCpuArray` | valore QFI (`u32`) | `u64` | Conteggio pacchetti per QFI (`0–63`) in Downlink | 
| `IP_EVENTS` | `RingBuf` | – | `GtpPair` | Eventi GTP-U (message type, TEID, QFI) verso userspace | 

*(Gli indirizzi IPv4 e i TEID vengono convertiti in Host Byte Order prima del lookup. Nella struct `Qer`, i campi `qfi`, `five_qi`, `dscp_green`, `dscp_yellow` e `_pad: [u8; 4]` occupano esattamente 8 byte allineati prima dei quattro `BucketParam`.)*

## 🎛️ Control Plane Dinamico (Mini-PFCP su UDP/JSON)

Il control plane rimane in ascolto sull'indirizzo passato via `--cp-addr` (default `127.0.0.1:8805`) e accetta datagrammi JSON mappati sull'enum `ControlCommand` (`"cmd"`):

| Comando (`cmd`) | Funzione | Campi principali | 
| ----- | ----- | ----- | 
| `add_uplink` | Crea/aggiorna sessione UL | `teid`, `far_id`, `far_action` (`forward`/`drop`), `outer_hdr_removed`, `qos` (opzionale: `five_qi`, `qer_id`, `qfi`, `gbr_mbps`, `mbr_mbps`, `burst_bytes`) | 
| `add_downlink` | Crea/aggiorna sessione DL | `ue_ip`, `far_id`, `far_action`, `peer_ip`, `peer_teid`, `local_ip`, `outer_hdr_creation`, `qos` (opzionale) | 
| `update_qer` | Aggiorna QoS a runtime | `five_qi` (opzionale), `qer_id`, `qfi`, `gbr_ul_mbps`, `mbr_ul_mbps`, `gbr_dl_mbps`, `mbr_dl_mbps`, `burst_bytes` | 
| `delete_uplink` | Rimuove PDR UL | `teid` | 
| `delete_downlink` | Rimuove PDR DL | `ue_ip` | 

### Validazione preventiva delle policy

Prima di qualsiasi scrittura sulle mappe eBPF, `apply_command` applica le seguenti guardie (restituendo `{"ok": false, "message": "..."}` in caso di violazione):

* **Default `five_qi`:** se omesso nel JSON, viene risolto automaticamente a `2` (`AF41`/`AF43`) quando $\text{MBR} > 0$, e a `9` (`CS0`) quando $\text{MBR} = 0$.

* **Range QFI e 5QI:** `qfi <= 63` (6 bit) e `five_qi` appartenente alla tabella standard supportata.

* **Coerenza `EF` (`1, 3, 65, 82..=85`):** policing stretto obbligatorio ($\text{MBR} > 0$ e $\text{GBR} = \text{MBR}$).

* **Coerenza GBR elastico (`2, 4, 66, 67`):** $\text{GBR} > 0$ se $\text{MBR} > 0$, e sempre $\text{GBR} \le \text{MBR}$.

* **Coerenza Non-GBR (`5, 6, 7, 8, 9, 69`):** $\text{GBR} = 0$ obbligatorio.

* **Burst e identificativi:** `qer_id != 0` e `burst_bytes >= 1500` quando $\text{MBR} > 0$.

**Esempi di invio a caldo tramite `nc`:**

```
# Sessione Uplink URLLC (5QI=82 -> EF 0xB8 -> classe 1:10, strict policing 10/10 Mbps)
echo '{"cmd":"add_uplink","teid":5582,"far_id":21,"far_action":"forward","qos":{"five_qi":82,"qer_id":21,"qfi":10,"gbr_mbps":10,"mbr_mbps":10,"burst_bytes":15000}}' | nc -u -w1 127.0.0.1 8805

# Sessione Uplink Video GBR (5QI=4 -> AF31/AF33 -> classi 1:31/1:32, GBR 10 / MBR 20 Mbps)
echo '{"cmd":"add_uplink","teid":5504,"far_id":23,"far_action":"forward","qos":{"five_qi":4,"qer_id":23,"qfi":12,"gbr_mbps":10,"mbr_mbps":20,"burst_bytes":15000}}' | nc -u -w1 127.0.0.1 8805

# Modifica banda live o declassamento a Non-QoS (0/0 -> 5QI=9 -> CS0 0x00 -> classe 1:42)
echo '{"cmd":"update_qer","qer_id":23,"qfi":12,"gbr_ul_mbps":0,"mbr_ul_mbps":0}' | nc -u -w1 127.0.0.1 8805

# Rimozione sessione Uplink
echo '{"cmd":"delete_uplink","teid":5504}' | nc -u -w1 127.0.0.1 8805

```

### Configurazione di test precaricata all'avvio

All'avvio, lo userspace inserisce le seguenti regole di base tramite `apply_command`:

| Direzione | Chiave | Regola | 
| ----- | ----- | ----- | 
| UL | TEID `9999` | FAR `1` (forward, decap), QER `1` (`five_qi=2`, `qfi=5`, `--gbr-ul` / `--mbr-ul`, burst `15000 B`) | 
| UL | TEID `8888` | FAR `2` (drop), `qos: None` | 
| DL | UE `10.60.0.1` | FAR `3` (encap verso gNB `10.0.3.2`, TEID `7001`, sorgente `10.0.3.1`), QER `2` (`five_qi=2`, `qfi=5`, `--gbr-dl` / `--mbr-dl`, burst `15000 B`) | 

Topologia: `ns-gnb` (`10.0.3.2`) $\rightleftarrows$ `veth-gnb`/`veth-n3` $\rightleftarrows$ UPF sull'host $\rightleftarrows$ `veth-n6`/`veth-dn` $\rightleftarrows$ `ns-dn` (`10.0.6.2`).

## 🛠️ Build ed Esecuzione

### 1. Compilazione (Kernel + Userspace)

Assicurati che il `Cargo.toml` del workspace sia configurato (profili `panic = 'abort'` nella root), poi:

```
cargo +nightly xtask build-ebpf
cargo build --release
```

### 2. Creazione Namespace (Topologia di Test)

Esegui `scripts/setup_netns.sh` per creare i namespace (`ns-gnb`, `ns-dn`) e le coppie `veth`:

```
sudo scripts/setup_netns.sh up
```

### 3. Avvio della UPF Full-Duplex

Una **singola istanza** gestisce contemporaneamente Uplink (`veth-n3` $\rightarrow$ `veth-n6`), Downlink (`veth-n6` $\rightarrow$ `veth-n3`), entrambi gli shaper TC a 4 classi e il Control Plane UDP (`127.0.0.1:8805`):

```
sudo ./target/release/upf_simply \
  --iface-ran veth-n3 --iface-dn veth-n6 \
  --mbr-ul 20 --gbr-ul 10 \
  --mbr-dl 20 --gbr-dl 10 \
  --non-qos-rate 10 --ef-rate 20 --link-rate 100 \
  --strip-bytes-ul 14 --strip-bytes-dl 58 \
  --cp-addr 127.0.0.1:8805
```

*(Vincoli HTB: sotto `1:1` assicurarsi che* $\text{ef-rate} + 2 \cdot \text{MBR} \le \text{link-rate}$ *e* $\text{GBR} + 0.01 \cdot \text{MBR} \le \text{MBR}$*; oltre* $\sim 100\text{ Mbps}$ *HTB segnala un quantum troppo grande).*

### 4. Test Automatici (Data Plane UL/DL e Control Plane Live)

I sender vanno fissati a una CPU con `taskset` poiché lo stato dei TAT risiede in una `PerCpuHashMap`. Con l'istanza Full-Duplex attiva, i test possono essere eseguiti in sequenza o **in parallelo** (assegnando CPU distinte, es. `-c 2` per UL e `-c 3` per DL, e aprendo un sink UDP sulla porta `5000` in `ns-dn` per evitare ICMP Port Unreachable di ritorno) senza riavviare la UPF.

**Uplink** (dentro `ns-gnb`, cattura in `ns-dn`):

```
sudo taskset -c 2 ip netns exec ns-gnb python3 scripts/upf_ul_selftest.py \
  --mbr 20 --gbr 10 --non-qos-rate 10 --tc-if veth-n6 \
  --green-class 1:21 --yellow-class 1:22 --non-qos-class 1:42 \
  --burst-bytes 15000 --htb-overhead 0

```

**Downlink** (dentro `ns-dn`, cattura in `ns-gnb`):

```
sudo taskset -c 3 ip netns exec ns-dn python3 scripts/upf_dl_selftest.py \
  --mbr 20 --gbr 10 --non-qos-rate 10 --tc-if veth-n3 \
  --green-class 1:21 --yellow-class 1:22 --non-qos-class 1:42 \
  --burst-bytes 15000 --htb-overhead 0

```

**Control Plane Dinamico Live & Multi-Classe 5QI** (sull'host):

```
sudo python3 scripts/test_cp_live.py --mbr-ul 20 --gbr-ul 10 --non-qos-rate 10 --ef-rate 20

```

| Suite / Fase | Verifica | 
| ----- | ----- | 
| **UL/DL Fase 1 (Funzionale)** | UL: parsing/decap con flag `0x30`/`0x32`/`0x34` e catene di extension header, marcatura `AF41` (`0x88`), TEID in drop e senza PDR. DL: tutti i campi dell'outer header (checksum, lunghezze, TEID, QFI, outer TOS `0x88`), integrità payload interno, limite MTU (`1456 B` vs `1457 B`), UE senza PDR | 
| **UL/DL Fase 2 (Sweep di rate)** | Uscita $\approx \min(\text{offerto}, \text{MBR})$; quota verde `AF41` (`0x88`) $\approx \min(\text{offerto}, \text{GBR}) / \min(\text{offerto}, \text{MBR})$, verificata su TOS e contatori HTB (`1:21` / `1:22`) | 
| **UL/DL Fase 3 (Dimensione)** | Con carico oltre l'MBR, l'uscita resta $\approx \text{MBR}$ per IP interno da `100`, `500`, `1000` e `1400 B` | 
| **UL/DL Fase 4–5 (Burst & Ricarica)** | Dopo quiete passano circa $\text{burst} + \text{MBR} \times t_{\text{invio}}$ byte; dopo pausa il bucket si ricarica | 
| **UL/DL Fase 6 (Non-QoS & Anti-Spoofing)** | Sessioni `qos=null` e Non-GBR `0/0`: pacchetti pre-marcati `0x88`/`0x98`/`0xB8` vengono ripuliti a `0x00` (checksum valido) e livellati dallo shaper `1:42` a `--non-qos-rate` | 
| **UL/DL Fase 7 (Isolamento Parallelo)** | Flusso QoS (`5QI=2`, `1:21`/`1:22`) e flusso Non-QoS saturato (`1:42`) in esecuzione simultanea senza degrado reciproco | 
| **Control Plane Live (Test 1–8)** | Validazione policy (`JSON`, `QFI > 63`, `5QI` invalido, `EF` strict, `Non-GBR` `gbr=0`, `GBR` `gbr>0`, `burst >= 1500`); ciclo di vita UL/DL; throttling live (`20 -> 2 Mbps`) e declassamento `0/0`; verifica multi-classe live per `5QI=82` (`EF` `0xB8` $\rightarrow$ `1:10`), `5QI=5` (`CS5` `0xA0` $\rightarrow$ `1:10`), `5QI=4` (`AF31`/`AF33` $\rightarrow$ `1:31`/`1:32`) e `5QI=6` (`AF11` `0x28` $\rightarrow$ `1:41`) | 

**Verifica manuale dell'header incapsulato:**

```
sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152

```

### Risultati di Validazione

Eseguendo tutte e tre le suite (`upf_ul_selftest.py`, `upf_dl_selftest.py`, `test_cp_live.py`) sulla stessa istanza Full-Duplex (`MBR = 20 Mbps`, `GBR = 10 Mbps`, `non-qos-rate = 10 Mbps`, `ef-rate = 20 Mbps`, `link-rate = 100 Mbps`, burst `15000 B`, `--strip-bytes-ul 14`, `--strip-bytes-dl 58`) si ottengono **0 FAIL su tutte le verifiche** con bilancio esatto al singolo pacchetto su **757.657 pacchetti** elaborati:

* **Bilancio XDP Uplink (`412.801` pacchetti esatti):**

  * **Per esito:** `287.560` decapsulati/forward + `20` drop FAR + `125.161` drop QoS + `60` nessun PDR = **`412.801`** (`0` errori di lookup o parsing).

  * **Per QFI:** `325.895` (`QFI 5`) + `65.786` (`QFI 9`) + `7.875` (`QFI 10` / `5QI=82`) + `20` (`QFI 11` / `5QI=5`) + `13.125` (`QFI 12` / `5QI=4`) + `20` (`QFI 13` / `5QI=6`) + `80` (`nessuna QFI`) = **`412.801`**.

  * **Flussi Non-QoS UL:** `52.620` pacchetti (`20` `CS5` in `1:10`, `20` `AF11` in `1:41`, `52.580` `CS0` verso `1:42`).

* **Bilancio XDP Downlink (`344.826` con PDR + `30` senza PDR):**

  * **Per esito:** `237.577` incapsulati/forward + `107.229` drop QoS + `20` errori MTU (`1457 B`) = **`344.826`**, identico alla somma `311.016` (`QFI 5`) + `33.790` (`QFI 7`) + `20` (`qos=null`).

  * **Flussi Non-QoS DL:** `33.810` pacchetti (`33.790` `QFI 7` + `20` `qos=null`).

* **Allineamento XDP** $\leftrightarrow$ **Linux TC HTB (tutte le 7 foglie verificate):**

  * **Albero QoS UL (`1:1`):** `234.960` pkt (`1:10`: `4.409` EF+CS5; `1:21`: `118.824` AF41; `1:22`: `102.963` AF43; `1:31`: `4.389` AF31; `1:32`: `4.375` AF33) — corrispondenza esatta al singolo pacchetto con `dropped 0` e precisione di `1000,00 B/pkt` grazie a `stab overhead`.

  * **Albero QoS DL (`1:1`):** `203.767` pkt (`1:21`: `108.984` AF41; `1:22`: `94.783` AF43) — corrispondenza esatta con `dropped 0`.

  * **Albero Non-QoS isolato (`1:40`):** `1:41` (`AF11` UL: `20/20` pkt, `20.000 B`); `1:42` (`CS0`: `26.944` pkt UL e `17.305` pkt DL livellati esattamente a `10.00 Mbps` sotto carico `20 Mbps`, con `backlog 0b 0p` finale).

* **Nota sul jitter del burst test su `veth`:** La fase burst da `~5–7 ms` può occasionalmente risentire del jitter dello scheduler software Python/kernel nella stima della durata d'invio. Le misure su `veth` validano la correttezza algoritmica, non le prestazioni di picco.

## ⚠️ Limiti Noti

* **Stato per-CPU:** I TAT risiedono in una `PerCpuHashMap`: ogni CPU ha il proprio bucket. Se i pacchetti di una stessa QER vengono distribuiti su $N$ CPU, il rate aggregato può raggiungere fino a $N \times \text{MBR}$. Al contrario, dividere i rate per $N$ limita un flusso su singolo core a $\text{MBR} / N$.

* **Classi HTB statiche rispetto a `update_qer`:** Il comando `update_qer` aggiorna istantaneamente i parametri Dual GCRA e i DSCP nel kernel XDP, ma le classi HTB sulle interfacce di uscita restano ai limiti configurati all'avvio. Ridurre l'MBR sotto il valore iniziale ha effetto immediato, mentre alzarlo oltre il ceil HTB resta limitato dallo shaper.

* **Checksum IPv4 interno (Uplink):** Il ricalcolo in `mark_dscp_checksum_ipv4hdr` assume header IPv4 standard senza opzioni ($\text{IHL} = 5$, 20 byte).

* **Solo IPv4, MTU 1500, Control Plane semplificato:** Il protocollo UDP/JSON emula le primitive 3GPP N4/PFCP ma non implementa la codifica binaria PFCP completa né il supporto IPv6.

* **Log ed eventi nel percorso caldo:** Le macro `info!` e la scrittura su `RingBuf` per ogni pacchetto GTP-U introducono overhead significativo e vanno rese opzionali (feature Cargo) prima dei benchmark ad alto packet-rate.

* **Overhead HTB fisso:** `--strip-bytes-ul` / `--strip-bytes-dl` sottraggono un valore costante per pacchetto: non coprono frame con tag VLAN o encapsulazioni di lunghezza diversa da quella standard.

## 🛣️ Roadmap e Traguardi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace via `RingBuf`.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU e per-QFI.

* \[x\] Parsing avanzato GTP-U ed estrazione QFI iterativa.

* \[x\] **Decapsulazione Uplink:** rimozione dell'header esterno tramite `bpf_xdp_adjust_head` e re-inoltro.

* \[x\] **Incapsulazione Downlink:** stack IPv4/UDP/GTP con ricalcolo checksum e controllo MTU.

* \[x\] **Inserimento dinamico del QFI:** Extension Header `0x85` in Downlink (validato su 6 bit).

* \[x\] **Rate Limiting QoS (trTCM):** Dual GCRA per-CPU con *hard drop* per traffico rosso (MBR), in UL e DL.

* \[x\] **Gestione Non-GBR / Non-QoS & Anti-Spoofing DSCP:** bypass dedicato (`CNT_NON_QOS`), marcatura attiva per tutte le classi e preservazione bit ECN.

* \[x\] **Mappatura Multi-Classe 5QI** $\rightarrow$ **DSCP (3GPP TS 23.501 / TS 29.244 + RFC 4594 / GSMA IR.34):** risoluzione nel Control Plane (`EF`, `CS5`, `AF41`/`AF43`, `AF31`/`AF33`, `AF11`, `CS0`) e shaper HTB + `fq_codel` a 4 classi (7 foglie) con maschera `0xfc`.

* \[x\] **Allineamento delle unità:** HTB che misura solo l'IP interno (`stab overhead` negativo).

* \[x\] **Control Plane Dinamico (Mini-PFCP):** listener asincrono Tokio UDP/JSON (`control.rs`) con validazione policy 5QI/QFI e aggiornamento thread-safe delle mappe a runtime (`add`, `update_qer`, `delete`).

* \[x\] **UPF Full-Duplex in un'unica istanza:** doppio attach XDP su `N3`/`N6` con dispatch su `IFACE_ROLE_MAP`, doppio shaper TC e contatori/tabelle separati per direzione (`COUNTERS_UL`/`DL`, `QFI_COUNTERS_UL`/`DL`).

* \[x\] **Suite di test automatici complete** (`upf_ul_selftest.py`, `upf_dl_selftest.py`, `test_cp_live.py`) con validazione a 0 FAIL su oltre 750.000 pacchetti.

* \[ \] **Ottimizzazione hot-path per benchmark:** disattivazione condizionale (feature Cargo / flag) di `info!` e `RingBuf` per pacchetto.

* \[ \] **Accelerazione `XDP_REDIRECT` (`bpf_fib_lookup`):** modalità `--fast-path` opzionale per bypassare lo stack IP Linux e confrontare le prestazioni rispetto al percorso `XDP_PASS + TC`.

* \[ \] Benchmark ad alte prestazioni con **TRex** (Mpps, throughput Gbps, latenza su NIC reale / DPDK).

* \[ \] Aggiornamento dinamico delle classi HTB (`tc class change`) alla ricezione di `update_qer`.

* \[ \] Test multi-flusso e multi-CPU (misura del comportamento aggregato del bucket per-CPU).

* \[ \] Corpus di pacchetti malformati (GTP troncato, lunghezze incoerenti, message type diversi da 255, IPv6, opzioni IP).
