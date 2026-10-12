use anyhow::{Context as _};
use aya::{maps::RingBuf, programs::{Xdp, XdpMode}};
use clap::Parser;
use ip_logger_common::IpPair;
#[rustfmt::skip]
use log::{warn};
use tokio::{signal, sync::{mpsc, oneshot::{self, Sender}}};
use std::{collections::HashMap, net::Ipv4Addr, time::Duration};
use crate::Command::{GetStats, LogPacket};

// Definisce gli argomenti da riga di comando
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth1")]
    iface: String,
}

#[derive(Debug)]
enum Command {

    // Dati del pacchetto Ipv4 ricevuti dal manager
    LogPacket {
        src: Ipv4Addr,
        _dst: Ipv4Addr,
    },

    // Response inviata al mittente
    GetStats {
        resp_tx: Sender<HashMap<Ipv4Addr,usize>>,

    }
}

// Avvolge il main in un "reattore" asincrono gestito da Tokio
// il main viene trasformato in una task 
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init(); // Inizializza il sistema di log standard di Rust nello user space

    // 1. CARICAMENTO DEL BYTECODE
    // Invece di leggere un file .o dal disco, include il bytecode eBPF precompilato 
    // direttamente nell'eseguibile Rust e lo allinea correttamente in memoria.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ip_logger"
    )))?;

    // 2. GESTIONE LOG ASINCRONI DAL KERNEL
    // Inizializza il canale per ricevere i log (es. info!(...)) dal kernel space.
    match aya_log::EbpfLogger::init(&mut ebpf) { 
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => { 
            // Avvolge il File Descriptor in un AsyncFd (sentinella asincrona).
            // Informiamo il sistema operativo di avvisarci SOLO quando ci sono dati da leggere (READABLE).
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            
            // Crea un task in background (thread leggero) per non bloccare il programma principale
            tokio::task::spawn(async move { 
                loop {
                    // .await: Il task si addormenta senza consumare CPU finché non arriva un log dal kernel
                    let mut guard = logger.readable_mut().await.unwrap();
                    
                    // Svuota il buffer interno formattando e stampando a schermo il testo
                    guard.get_inner_mut().flush(); 
                    
                    // Resetta lo stato di allerta, preparandosi a ricevere il prossimo log
                    guard.clear_ready(); 
                }
            });
        }
    }

    // 3. ESTRAZIONE E INIEZIONE DEL PROGRAMMA XDP
    let Opt { iface } = opt;
    // Cerca la funzione specificata nel bytecode e la converte in un programma XDP
    let program: &mut Xdp = ebpf.program_mut("ip_logger").unwrap().try_into()?; 
    
    program.load()?; // Inietta fisicamente il bytecode nel kernel tramite la syscall bpf()
    
    // Aggancia il programma XDP all'interfaccia di rete. Si usa Skb (SKB_MODE) per 
    // garantire la compatibilità con interfacce virtuali (es. WSL).
    program.attach(&iface, XdpMode::Skb)
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    // 4. INIZIALIZZAZIONE DEL RING BUFFER
    // Cerca la mappa "IP_EVENTS" e istanzia il gestore per estrarre gli eventi passati dal kernel
    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("IP_EVENTS").unwrap()).expect("Errore nella ricerca della mappa"); 
    
    println!("In ascolto dei pacchetti..... Premi Ctrl + C per uscire");

    // 5. CREAZIONE DEL TASK MANAGER (MESSAGE PASSING)
    let (tx, mut rx) = mpsc::channel::<Command>(1000);
    
    let _manager = tokio::spawn(async move {

        let mut ip_counts: HashMap<Ipv4Addr, usize> = HashMap::new();
        while let Some(cmd) = rx.recv().await {

            match cmd {
                LogPacket { src, _dst} => {
                    ip_counts.entry(src).and_modify(|e| *e +=1).or_insert(0);
                }
                GetStats {resp_tx} => {

                    let stast = ip_counts.clone();
                    let _ = resp_tx.send(stast);
                }
            }
        }
    });

    // 6. RICHIESTA DI REPORT ogni 5 secondi
        let tx_report = tx.clone();
        // creazione del task report
        tokio::spawn(async move {

            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let (resp_tx, resp_rx) = oneshot::channel::<HashMap<Ipv4Addr, usize>>();
                let cmd = GetStats { resp_tx };

                if tx_report.send(cmd).await.is_ok() {
                    let resp = resp_rx.await.unwrap();

                    let mut resp_vec: Vec<(&Ipv4Addr, &usize)> = resp.iter().collect();
                    resp_vec.sort_by(|a, b| b.1.cmp(a.1));
                    println!("STATISTICHE ATTUALI:");
                    for i in resp_vec {
                        println!("IP: {} -> {} pacchetti", i.0, i.1);
                    }

                }
            } 
        });

    // 7. CICLO DI LETTURA E INVIO DATI AL MANAGER
    loop {
        // Estrae iterativamente tutti gli eventi in coda nel ring buffer (svuotandolo)
        while let Some(item) = ring_buf.next() { 
            
            if item.len() == std::mem::size_of::<IpPair>() {
                // Esegue un cast "unsafe" per convertire i byte crudi (raw) nella struttura Rust
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const IpPair) }; 
                
                // Converte gli interi grezzi estratti in indirizzi IPv4 leggibili
                let ip_sorgente = Ipv4Addr::from(u32::from_be(event.src));
                let ip_destinazione = Ipv4Addr::from(u32::from_be(event.dst));

                let cmd = LogPacket { 
                    src: ip_sorgente, 
                    _dst: ip_destinazione
                };

                tx.send(cmd).await.unwrap();
            }
        }

        
        // 8. ATTESA ASINCRONA INTELLIGENTE
        // finiti i pkt nel ring buffer si esegue quanto segue
        // tokio::select! mette in competizione due eventi. Il primo che si verifica "vince" e viene eseguito.
        tokio::select! {
            _ = signal::ctrl_c() => {
                // Se l'utente preme Ctrl+C, il reattore lo intercetta e interrompiamo il loop
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                // Se passano 500ms senza segnali, il timer scade.
                // Il loop riparte dall'inizio e torna a chiamare ring_buf.next() per i nuovi pacchetti.
            }
        }
    }
    
    println!("");
    println!("Exiting...");
    Ok(())
}