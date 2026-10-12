# ipLogger

ipLogger è un'applicazione di monitoraggio di rete basata su eBPF (eXpress Data Path - XDP) scritta interamente in Rust utilizzando il framework **Aya**. Il progetto ha lo scopo di intercettare i pacchetti IPv4 in entrata, estrarre l'indirizzo IP sorgente e quello di destinazione, e stamparli a schermo in tempo reale.

## Architettura del Progetto

Il progetto è strutturato in tre componenti principali che comunicano tra loro:

*   **Kernel Space (Programma eBPF)**
    *   Opera al livello più basso dello stack di rete (tramite hook XDP) analizzando i byte crudi di ogni pacchetto in arrivo.
    *   Implementa una funzione sicura di controllo dei limiti di memoria (`ptr_at`) per soddisfare le rigide regole del Verifier eBPF del kernel Linux.
    *   Verifica che il pacchetto sia di tipo IPv4, ne estrae gli IP (byte grezzi) e tenta di riservare uno spazio all'interno di una mappa condivisa di tipo `RingBuf`.
    *   Scrive i dati estratti nel buffer, conferma l'invio (submit) allo User Space, e infine restituisce `XDP_PASS` per lasciare che il pacchetto continui il suo normale percorso nel sistema operativo.

*   **User Space**
    *   Scritta in Rust e basata sul runtime asincrono **Tokio**, l'applicazione carica il bytecode eBPF, inietta il codice e lo aggancia all'interfaccia di rete scelta dall'utente.
    *   Si mette in ascolto sul Ring Buffer estraendo ciclicamente i byte grezzi, ne effettua il casting sicuro verso la struttura dati Rust, converte i dati da Network Order (Big Endian) nel formato leggibile (IpAddr) e infine stampa il risultato a schermo (`IP SORGENTE -> IP DESTINAZIONE`).
    *   Imposta, anche un file descriptor asincrono (`AsyncFd`) per mettersi in ascolto e stampare automaticamente a schermo anche i log di debug (`info!`) generati direttamente dal Kernel.
    L'applicazione garantisce un'uscita pulita alla pressione di `Ctrl+C`. Sfruttando la macro `tokio::select!`, il programma monitora simultaneamente l'estrazione dei pacchetti dal Ring Buffer e l'arrivo del segnale di interruzione `SIGINT` (Ctrl + C). 

*   **Common (Strutture Condivise)**
    *   Un modulo condiviso che definisce la struttura dati `IpPair` contenente due interi a 32 bit (`src` e `dst`).
    *   La struttura utilizza l'attributo `#[repr(C)]`. Questo impone al compilatore Rust di allineare la memoria esattamente come farebbe un compilatore C, prevenendo errori critici di lettura durante il passaggio dei dati grezzi dal kernel all'user space.

## Tecnologie Utilizzate

*   **Rust**: Linguaggio principale per un'implementazione sicura ed efficiente sia lato kernel che user space.
*   **Aya**: Il framework che permette di compilare e gestire i programmi eBPF nativamente in Rust, eliminando la necessità di interfacciarsi manualmente con librerie C come `libbpf`.
*   **Tokio**: Runtime asincrono utilizzato per l'estrazione intelligente non-bloccante degli eventi, riducendo a zero il consumo di CPU quando non ci sono pacchetti da processare.
*   **Clap**: Gestore degli argomenti CLI.

## Requisiti

*   Una macchina Linux (o WSL2 con filesystem `bpffs` montato).
*   Privilegi di amministratore (root) necessari per caricare e agganciare programmi eBPF al kernel.

## Utilizzo

Per avviare l'applicazione in ascolto, utilizza i privilegi di root specificando l'interfaccia di rete tramite il flag `-i` o `--iface`. Se omessa, verrà utilizzata l'interfaccia predefinita (`eth0`).

```bash
sudo ./ip_logger --iface eth0