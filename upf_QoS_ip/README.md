# UPF-Qos-Ip: Prototipo UPF 5G in eBPF/Rust (Architettura Modulare)

Prototipo di data plane e control plane leggero per una **UPF 5G** (User Plane Function) scritto in **Rust** utilizzando **eBPF (Aya)** e **Tokio**.

Un singolo programma **XDP** agganciato simultaneamente alle interfacce **RAN** (N3) e **Data Network** (N6) intercetta il traffico in modalità **Full-Duplex**, esegue il dispatch tra flussi Uplink e Downlink in base all'interfaccia di ingresso (`ingress_ifindex`), analizza gli header GTP-U (inclusi gli Extension Headers per ricavare il **QFI**) e applica le logiche di routing e QoS basate sulle tabelle **PDR** (Packet Detection Rule), **FAR** (Forwarding Action Rule) e **QER** (QoS Enforcement Rule) caricate in mappe eBPF.

Lo userspace espone un **Control Plane asincrono su UDP/JSON** (porta standard PFCP `8805`) per aggiungere, modificare e rimuovere regole a runtime senza interrompere il data plane, legge gli eventi GTP-U tramite `RingBuf` e raccoglie statistiche separate per direzione (Uplink/Downlink) e per singolo flusso QoS tramite mappe per-CPU.

> 🚀 **Stato:** Prototipo **Full-Duplex** validato funzionalmente in **Uplink, Downlink e gestione dinamica a runtime** su una singola istanza UPF in topologia a namespace (`veth`). L'architettura **trTCM (Two Rate Three Color Marker)** ibrida è completa su entrambe le direzioni: XDP esegue il policing lock-free (Dual GCRA) e la marcatura dinamica (DSCP), delegando lo shaping e l'accodamento al **Linux Traffic Control (TC)** configurato su entrambe le interfacce di egress. La QoS è stata verificata su singolo core per direzione; il comportamento multi-CPU è documentato tra i [limiti noti](#️-limiti-noti).

## ✨ Funzionalità Attuali

* **UPF Full-Duplex (Singola Istanza N3 + N6):** Un unico programma XDP viene caricato una sola volta e agganciato contemporaneamente alle interfacce `--iface-ran` (RAN) e `--iface-dn` (DN). Il dispatch non dipende più solo dalla porta UDP, ma identifica la sorgente leggendo `ingress_ifindex` e consultando `IFACE_ROLE_MAP` (`IFACE_ROLE_RAN` / `IFACE_ROLE_DN`), in aderenza al concetto 3GPP di *Source Interface*.

* **Control Plane Dinamico Asincrono (Mini-PFCP su UDP/JSON):** Il modulo `control.rs` esegue un listener Tokio `UdpSocket` (default `127.0.0.1:8805`) che condivide in sicurezza le mappe eBPF tramite `ControlState` (`Arc<Mutex<...>>` con ownership acquisita via `take_map`). Supporta inserimento, aggiornamento QoS live (senza azzerare i TAT dei flussi attivi) e rimozione delle sessioni tramite comandi JSON, rispondendo con esiti strutturati `{"ok": bool, "message": "..."}`. Le scritture seguono l'ordine sicuro `QER_STATE -> QER -> FAR -> PDR` (inverso in cancellazione) per garantire consistenza con i lettori lock-free in XDP.

* **Architettura XDP Modulare:** Codice kernel separato in moduli logici (`net`, `gtp`, `uplink`, `downlink`, `maps`), privo di puntatori invalidi (*stale pointers*) dopo le chiamate a `bpf_xdp_adjust_head`.

* **Parsing XDP e Gestione Errori Unificata per Direzione:** Validazione della catena Ethernet $\rightarrow$ IPv4 $\rightarrow$ UDP $\rightarrow$ GTP-U v1. Gli errori sono mappati tramite `Result<T, u32>` e instradati automaticamente dall'entrypoint XDP nella mappa contatori della direzione corretta (`COUNTERS_UL` o `COUNTERS_DL`).

* **Decapsulazione Uplink & Incapsulazione Downlink:** Rimozione e aggiunta dinamica di header (IPv4, UDP, GTP-U ed Extension Headers) con ricalcolo del checksum IPv4 dell'header esterno. In downlink l'IP interno può essere lungo al massimo **1456 B** (outer = 1500 B): oltre tale soglia il pacchetto non viene incapsulato e incrementa `CNT_ERR` in `COUNTERS_DL`.

* **Gestione Extension Headers:** Decodifica iterativa in ingresso (Uplink), anche con catene di più extension header, ed emissione in uscita (Downlink) del container `0x85` (*PDU Session Container*) con il **QFI** letto dalla QER.

* **Rate Limiting in XDP (trTCM / Dual GCRA, stato per-CPU):** Per ogni pacchetto si calcola il costo temporale $\text{lunghezza\_IP\_interno} \times \text{ns\_per\_byte}$ (in aritmetica a virgola fissa Q30) e si aggiornano due TAT (*Theoretical Arrival Time*), uno per il CIR (GBR) e uno per il PIR (MBR):

  * **Rosso (**$> \text{MBR}$**):** Il nuovo TAT di picco eccede la burst tolerance. XDP esegue `XDP_DROP`, senza aggiornare alcun TAT.

  * **Giallo (tra GBR e MBR):** Il traffico eccede il CIR ma non il PIR. Passa, aggiorna solo il TAT di picco, e XDP **marca il TOS/DSCP** (`0x38`, DSCP 14 / AF13) ricalcolando il checksum. In uplink la marcatura avviene sull'IP interno (prima della decap), in downlink sull'header esterno (in fase di encap).

  * **Verde (**$< \text{GBR}$**):** Rispetta la banda garantita. Aggiorna entrambi i TAT; il TOS non viene modificato.

  La burst tolerance include il costo del pacchetto corrente, quindi deve essere almeno pari al pacchetto più grande: il progetto usa **15000 B** di default per CIR e PIR.

* **Traffic Control (TC) Shaping Bidirezionale (HTB & `fq_codel`):** Il control plane istanzia automaticamente due alberi `qdisc` HTB speculari sulle rispettive interfacce di egress (`iface_dn` per l'Uplink, `iface_ran` per il Downlink), con filtri `u32` sul TOS impostato da XDP:

  * **Root `1:1`:** `rate = ceil = MBR`.

  * **Coda Verde `1:10`:** `rate = GBR`, `ceil = MBR`.

  * **Coda Gialla `1:20`:** `rate` pari all'1% dell'MBR, `ceil = MBR`; funge anche da classe di default per pacchetti con TOS non riconosciuto.

  * Le code foglia sono configurate con **`fq_codel`** per contenere la latenza di accodamento e garantire equità sui flussi consentiti (in alternativa a `pfifo`, presente come opzione commentata).

* **Allineamento delle Unità HTB (`--strip-bytes-ul` / `--strip-butes-dl`):** Il policer XDP conta l'IP interno, mentre l'HTB conta di default l'intero frame. Le opzioni `--strip-bytes-ul` (default **14 B**: Ethernet su N6) e           `--strip-bytes-dl` (default **58 B**: Ethernet + outer IP/UDP/GTP-U/Ext su N3) installano una size table `stab overhead -N` sulle rispettive qdisc root, allineando le misure tra XDP e TC. Impostando `0` si ottiene l'HTB standard.

* **Telemetria Separata e Report Tabellare:** Eventi per pacchetto GTP-U (`GtpPair`) tramite `RingBuf`; ogni 5 secondi e alla chiusura (`Ctrl+C`), lo userspace stampa una tabella affiancata (`Uplink | Downlink | Totale`) per i contatori XDP e per ogni QFI attivo, seguita dalle statistiche `tc -s class` di entrambe le interfacce di uscita.

## 🏗️ Architettura del Flusso

```
                           [ Control Plane UDP/JSON ]
                         Tokio UdpSocket (127.0.0.1:8805)
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
                       │                          ├─ Lookup QER_MAP (qer_id)
      UL_PDR_MAP[TEID] ┤                          ├─ FAR Action (DROP/FWD)
       FAR_MAP[far_id] ┴─ DROP/FWD                │
                       │                          │
        [ trTCM Policing (Dual GCRA) ]   [ trTCM Policing (Dual GCRA) ]
         (CIR/PIR UL, Drop se rosso)      (CIR/PIR DL, Drop se rosso)
                       │                          │
      [ Marcatura TOS 0x38 su IP int ]   [ Incapsulazione 44 B + QFI 0x85 ]
                       │                 (TOS 0x38 su IP ext + Checksum)
           [ Decapsulazione ]                     │
         (adjust_head positivo)                   │
                       │                          │
               COUNTERS_UL / QFI_UL       COUNTERS_DL / QFI_DL
                   XDP_PASS                   XDP_PASS
                       │                          │
 ══════════════════════▼══════════════════════════▼═════════════════════════
        [ TC Egress UL: veth-n6 ]        [ TC Egress DL: veth-n3 ]
        HTB (MBR) + stab -14 B           HTB (MBR) + stab -58 B
               │                                  │
       ┌───────┴───────┐                  ┌───────┴───────┐
   TOS 0x00        TOS 0x38           TOS 0x00        TOS 0x38
 [ Verde 1:10 ]  [ Giallo 1:20 ]    [ Verde 1:10 ]  [ Giallo 1:20 ]
   (fq_codel)      (fq_codel)         (fq_codel)      (fq_codel)
       └───────┬───────┘                  └───────┬───────┘
               ▼                                  ▼
           DN (ns-dn)                        gNB (ns-gnb)

```

## 🗺️ Mappe eBPF

| Nome Mappa | Tipo | Chiave | Valore | Scopo | 
| ----- | ----- | ----- | ----- | ----- | 
| `IFACE_ROLE_MAP` | `HashMap` | `ifindex` (`u32`) | Ruolo (`u8`: `RAN` / `DN`) | Dispatch Full-Duplex basato sull'interfaccia di ingresso | 
| `UL_PDR_MAP` | `HashMap` | TEID (`u32`) | `Pdr { far_id, qer_id, outer_hdr_removed }` | Regole di forwarding Uplink | 
| `DL_PDR_MAP` | `HashMap` | IP UE (`u32`) | `Pdr { far_id, qer_id, outer_hdr_removed }` | Regole di forwarding Downlink (routing IP) | 
| `FAR_MAP` | `HashMap` | `far_id` (`u32`) | `Far { action, outer_hdr_creation, peer_ip, peer_teid, local_ip }` | Azione (`FORWARD`/`DROP`) e parametri del tunnel | 
| `QER_MAP` | `HashMap` | `qer_id` (`u32`) | `Qer { qfi, cir_ul, pir_ul, cir_dl, pir_dl }` | Parametri QoS (`ns_per_byte` Q30 e `burst_tolerance_ns`) | 
| `QER_STATE_MAP` | `PerCpuHashMap` | `qer_id` (`u32`) | `QerState { tat_cir_ul, tat_pir_ul, tat_cir_dl, tat_pir_dl }` | Stato dei TAT del Dual GCRA, lock-free | 
| `COUNTERS_UL` | `PerCpuArray` | indice (`u32`) | `u64` | Statistiche ed errori specifici del ramo Uplink | 
| `COUNTERS_DL` | `PerCpuArray` | indice (`u32`) | `u64` | Statistiche ed errori specifici del ramo Downlink | 
| `QFI_COUNTERS_UL` | `PerCpuArray` | valore QFI (`u32`) | `u64` | Conteggio pacchetti per QFI (0–63) in Uplink | 
| `QFI_COUNTERS_DL` | `PerCpuArray` | valore QFI (`u32`) | `u64` | Conteggio pacchetti per QFI (0–63) in Downlink | 
| `IP_EVENTS` | `RingBuf` | – | `GtpPair` | Eventi GTP-U (message type, TEID, QFI) verso userspace | 

*(Gli indirizzi IPv4 e i TEID vengono convertiti in Host Byte Order prima del lookup).*

## 🎛️ Control Plane Dinamico (Mini-PFCP su UDP/JSON)

Il control plane rimane in ascolto sull'indirizzo passato via `--cp-addr` (default `127.0.0.1:8805`) e accetta datagrammi JSON mappati sull'enum `ControlCommand` (`"cmd"`):

| Comando (`cmd`) | Funzione | Campi principali | 
| ----- | ----- | ----- | 
| `add_uplink` | Crea/aggiorna sessione UL | `teid`, `far_id`, `far_action` (`forward`/`drop`), `outer_hdr_removed`, `qos` (opzionale) | 
| `add_downlink` | Crea/aggiorna sessione DL | `ue_ip`, `far_id`, `far_action`, `peer_ip`, `peer_teid`, `local_ip`, `outer_hdr_creation`, `qos` | 
| `update_qer` | Aggiorna QoS a runtime | `qer_id`, `qfi`, `gbr_ul_mbps`, `mbr_ul_mbps`, `gbr_dl_mbps`, `mbr_dl_mbps`, `burst_bytes` | 
| `delete_uplink` | Rimuove PDR UL | `teid` | 
| `delete_downlink` | Rimuove PDR DL | `ue_ip` | 

Ogni comando viene validato prima della scrittura (es. `qer_id != 0`, `gbr <= mbr`). Errori di sintassi JSON o parametri invalidi vengono restituiti al client con `{"ok": false, "message": "..."}` senza interrompere il servizio né alterare le regole esistenti.

**Esempi di invio a caldo tramite `nc`:**

```
# Aggiunta sessione Uplink sul TEID 5555 (QFI 9, GBR 10 Mbps, MBR 20 Mbps)
echo '{"cmd":"add_uplink","teid":5555,"far_id":10,"far_action":"forward","qos":{"qer_id":10,"qfi":9,"gbr_mbps":10,"mbr_mbps":20,"burst_bytes":15000}}' | nc -u -w1 127.0.0.1 8805

# Modifica banda live (throttling da 20 Mbps a 2 Mbps senza resettare i TAT)
echo '{"cmd":"update_qer","qer_id":10,"qfi":9,"gbr_ul_mbps":1,"mbr_ul_mbps":2}' | nc -u -w1 127.0.0.1 8805

# Rimozione sessione Uplink
echo '{"cmd":"delete_uplink","teid":5555}' | nc -u -w1 127.0.0.1 8805

```

### Configurazione di test precaricata all'avvio

All'avvio, lo userspace inserisce le seguenti regole di base passando direttamente dalla pipeline `apply_command`:

| Direzione | Chiave | Regola | 
| ----- | ----- | ----- | 
| UL | TEID `9999` | FAR `1` (forward, decap), QER `1` (`qfi=5`, GBR/MBR da CLI) | 
| UL | TEID `8888` | FAR `2` (drop), nessuna QER | 
| DL | UE `10.60.0.1` | FAR `3` (encap verso gNB `10.0.3.2`, TEID `7001`, sorgente `10.0.3.1`), QER `2` (`qfi=5`, GBR/MBR da CLI) | 

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
sudo bash scripts/setup_netns.sh
```

### 3. Avvio della UPF Full-Duplex

Una **singola istanza** gestisce contemporaneamente Uplink (`veth-n3` $\rightarrow$ `veth-n6`), Downlink (`veth-n6` $\rightarrow$ `veth-n3`), entrambi gli shaper TC e il Control Plane UDP (`127.0.0.1:8805`):

```
sudo ./target/release/upf_simply \
  --iface-ran veth-n3 --iface-dn veth-n6 \
  --mbr 20 --gbr 10 \
  --strip-bytes-ul 14 --strip-bytes-dl 58 \
  --cp-addr 127.0.0.1:8805

```

*(Vincolo HTB sulle classi figlie:* $\text{GBR} + 0.01 \cdot \text{MBR} \le \text{MBR}$*; oltre* $\sim 100\text{ Mbps}$ *HTB segnala un quantum troppo grande).*

### 4. Test Automatici (Data Plane UL/DL e Control Plane Live)

I sender vanno fissati a una CPU con `taskset` poiché lo stato dei TAT risiede in una `PerCpuHashMap`. Con l'istanza Full-Duplex attiva, i test possono essere eseguiti in sequenza o **in parallelo** (assegnando CPU distinte, es. `-c 2` per UL e `-c 3` per DL) senza riavviare la UPF.

**Uplink** (dentro `ns-gnb`, cattura in `ns-dn`):

```
sudo taskset -c 2 ip netns exec ns-gnb python3 scripts/upf_ul_selftest.py \
  --mbr 20 --gbr 10 --tc-if veth-n6 \
  --green-class 1:10 --yellow-class 1:20 \
  --burst-bytes 15000 --htb-overhead 0

```

**Downlink** (dentro `ns-dn`, cattura in `ns-gnb`):

```
sudo taskset -c 3 ip netns exec ns-dn python3 scripts/upf_dl_selftest.py \
  --mbr 20 --gbr 10 --tc-if veth-n3 \
  --green-class 1:10 --yellow-class 1:20 \
  --burst-bytes 15000 --htb-overhead 0

```

**Control Plane Dinamico Live** (sull'host, invia comandi UDP e traffico GTP-U reale tra `ns-gnb` e `ns-dn`):

```
sudo python3 scripts/test_cp_live.py
```

| Suite / Fase | Verifica | 
| ----- | ----- | 
| **UL/DL Fase 1 (Funzionale)** | UL: parsing e decap con flag `0x30`/`0x32`/`0x34` e catena di extension header, TEID in drop e senza PDR. DL: ogni campo dell'outer header (checksum, lunghezze, TEID, QFI), integrità payload interno, limite MTU (`1456 B` vs `1457 B`), UE senza PDR | 
| **UL/DL Fase 2 (Sweep di rate)** | Uscita $\approx \min(\text{offerto}, \text{MBR})$; quota verde $\approx \min(\text{offerto}, \text{GBR}) / \min(\text{offerto}, \text{MBR})$, verificata su TOS e contatori HTB | 
| **UL/DL Fase 3 (Dimensione)** | Con carico oltre l'MBR, l'uscita resta $\approx \text{MBR}$ per IP interno da 100, 500, 1000 e 1400 B | 
| **UL/DL Fase 4–5 (Burst & Ricarica)** | Dopo quiete passano circa $\text{burst} + \text{MBR} \times t_{\text{invio}}$ byte; dopo pausa il bucket si ricarica | 
| **Control Plane Live** | Rifiuto JSON malformati e `GBR > MBR`; creazione sessione live (TEID `5555`); throttling live `update_qer` ($20 \rightarrow 2\text{ Mbps}$); rilascio sessione `delete_uplink` e verifica di `PDR NON TROVATA` | 

**Verifica manuale dell'header incapsulato:**

```
sudo ip netns exec ns-gnb tcpdump -i veth-gnb -n -vv -X udp port 2152
```

### Risultati di Validazione

Eseguendo in sequenza sulla stessa istanza Full-Duplex (`MBR = 20 Mbps`, `GBR = 10 Mbps`, burst `15000 B`, `--strip-ul 14`, `--strip-dl 58`) le suite `upf_ul_selftest.py`, `upf_dl_selftest.py` e `test_cp_live.py`:

* **Control Plane Live (`test_cp_live.py`):** **100% PASS** su tutte le verifiche. Con `update_qer` da `20 Mbps` a `2 Mbps` (`GBR = 1 Mbps`) su un flusso offerto a `15 Mbps`, il throughput misurato si attesta a **`2.04 Mbps`** (`389` pacchetti verdi e `375` gialli su 3 s), in pieno accordo con il modello teorico Dual GCRA.

* **Isolamento Full-Duplex e Bilancio Esatto dei Contatori:** Su oltre **600.000 pacchetti** elaborati in una singola sessione:

  * **Uplink:** `204.539` decapsulati + `20` drop FAR + `110.206` drop QoS + `100` nessun PDR = **`314.865`**, identico alla somma dei QFI (`292.145` QFI 5 + `22.640` QFI 9 + `80` senza QFI); `0` incapsulazioni e `0` errori.

  * **Downlink:** `191.739` incapsulati + `100.595` drop QoS + `20` errori MTU (`1457 B`) = **`292.354`**, identico a `QFI 5 = 292.354` (più `20` pacchetti verso UE senza PDR); `0` decapsulazioni.

  * **Traffic Control:** `dropped 0` su entrambe le gerarchie HTB/`fq_codel` (`veth-n6` e `veth-n3`), con corrispondenza al singolo pacchetto tra policer XDP e classi Verde (`1:10`) / Gialla (`1:20`).

* **Nota sul jitter del burst test su `veth`:** La fase burst da `~5–7 ms` può occasionalmente risentire del jitter dello scheduler software Python/kernel nella stima della durata d'invio. Le misure su `veth` fino a 60 Mbps validano la correttezza algoritmica, non le prestazioni di picco.

## ⚠️ Limiti Noti

* **Stato per-CPU:** I TAT risiedono in una `PerCpuHashMap`: ogni CPU ha il proprio bucket. Se i pacchetti di una stessa QER vengono distribuiti su $N$ CPU, il rate aggregato può raggiungere fino a $N \times \text{MBR}$. Al contrario, dividere i rate per $N$ limita un flusso su singolo core a $\text{MBR} / N$.

* **Classi HTB statiche rispetto a `update_qer`:** Il comando `update_qer` aggiorna istantaneamente i parametri Dual GCRA nel kernel XDP (policing e marcatura), ma le classi HTB del Traffic Control sulle interfacce di uscita restano ai limiti configurati all'avvio. Di conseguenza, ridurre l'MBR sotto il valore iniziale ha effetto immediato, mentre alzarlo oltre il ceil HTB resta limitato dallo shaper.

* **Marcatura del verde in uplink:** Il verde non azzera il TOS: un pacchetto interno con TOS diverso da `0x00` e `0x38` finisce nella classe di default (gialla), e uno già marcato `0x38` risulta giallo anche se conforme.

* **Checksum IPv4 interno (uplink, giallo):** Il ricalcolo assume $\text{IHL} = 5$; la lunghezza del pacchetto viene letta prima di verificare che il pacchetto interno sia IPv4.

* **Solo IPv4, MTU 1500, Control Plane semplificato:** Il protocollo UDP/JSON emula le primitive di sessione 5G ma non implementa la codifica binaria completa del protocollo 3GPP PFCP né la gestione di IPv6.

* **Log ed eventi nel percorso caldo:** Le macro `info!` e la scrittura su `RingBuf` per ogni pacchetto GTP-U introducono overhead significativo e vanno rese opzionali o disattivate nei benchmark ad alto packet-rate.

* **Overhead HTB fisso:** `--strip-ul` / `--strip-dl` sottraggono un valore costante per pacchetto: non coprono frame con tag VLAN o encapsulazioni di lunghezza diversa da quella prevista.

## 🛣️ Roadmap e Traguardi

* \[x\] Parsing base GTP-U in XDP ed eventi verso userspace via `RingBuf`.

* \[x\] Gestione PDR e FAR tramite mappe eBPF.

* \[x\] Contatori di esito per-CPU e per-QFI.

* \[x\] Parsing avanzato GTP-U ed estrazione QFI iterativa.

* \[x\] **Decapsulazione Uplink:** rimozione dell'header esterno tramite `bpf_xdp_adjust_head` e re-inoltro.

* \[x\] **Incapsulazione Downlink:** stack IPv4/UDP/GTP con ricalcolo checksum e controllo MTU.

* \[x\] **Inserimento dinamico del QFI:** Extension Header `0x85` in Downlink.

* \[x\] **Rate Limiting QoS (trTCM):** Dual GCRA con *hard drop* per traffico rosso (MBR), in UL e DL.

* \[x\] **Marcatura Dinamica (DSCP):** TOS `0x38` per il traffico giallo.

* \[x\] **Traffic Control (TC) Shaping:** HTB + `fq_codel` con classi verde/gialla e filtri `u32` sul TOS.

* \[x\] **Allineamento delle unità:** HTB che misura solo l'IP interno (`stab overhead` negativo).

* \[x\] **Test automatici UL e DL** con script Scapy/`tcpdump` e verifica dei contatori.

* \[x\] **Control Plane Dinamico (Mini-PFCP):** listener asincrono Tokio UDP/JSON (`control.rs`) con aggiornamento thread-safe delle mappe a runtime (`add`, `update_qer`, `delete`) e suite di test live (`test_cp_live.py`).

* \[x\] **UPF Full-Duplex in un'unica istanza:** doppio attach XDP su `N3`/`N6` con dispatch su `IFACE_ROLE_MAP`, doppio shaper TC e contatori/tabelle separati per direzione (`COUNTERS_UL`/`DL`, `QFI_COUNTERS_UL`/`DL`).

* \[ \] **Accelerazione `XDP_REDIRECT` (`bpf_fib_lookup`):** modalità `--fast-path` opzionale per bypassare lo stack IP Linux e confrontare le prestazioni rispetto al percorso `XDP_PASS + TC`.

* \[ \] **Ottimizzazione hot-path per benchmark:** disattivazione condizionale (feature Cargo / flag) di `info!` e `RingBuf` per pacchetto.

* \[ \] Aggiornamento dinamico delle classi HTB (`tc class change`) alla ricezione di `update_qer`.

* \[ \] Test multi-flusso e multi-CPU (misura del comportamento aggregato del bucket per-CPU).

* \[ \] Corpus di pacchetti malformati (GTP troncato, lunghezze incoerenti, message type diversi da 255, IPv6, opzioni IP).

* \[ \] Benchmark ad alte prestazioni con **TRex** (Mpps, throughput Gbps, latenza su NIC reale / DPDK).