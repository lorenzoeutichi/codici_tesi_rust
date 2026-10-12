use anyhow::{Context as _};
use aya::{maps::RingBuf, programs::{Xdp, XdpMode}};
use clap::Parser;
use ip_logger_common::IpPair;
#[rustfmt::skip]
use log::{warn};
use tokio::signal;
use std::{net::Ipv4Addr, time::Duration};

// Definisce gli argomenti da riga di comando
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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
    
    println!("In ascolto dei pacchetti..... Premi Ctrl +C per uscire");

    // 5. CICLO DI LETTURA E CHIUSURA (POLLING)
    loop {
        // Estrae iterativamente tutti gli eventi in coda nel ring buffer (svuotandolo)
        while let Some(item) = ring_buf.next() { 
            
            if item.len() == std::mem::size_of::<IpPair>() {
                // Esegue un cast "unsafe" per convertire i byte crudi (raw) nella struttura Rust
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const IpPair) }; 
                
                // Converte gli interi grezzi estratti in indirizzi IPv4 leggibili
                let ip_sorgente = Ipv4Addr::from(u32::from_be(event.src));
                let ip_destinazione = Ipv4Addr::from(u32::from_be(event.dst));

                println!("{} -> {}", ip_sorgente, ip_destinazione);
            }
        }

        // 6. ATTESA ASINCRONA INTELLIGENTE
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