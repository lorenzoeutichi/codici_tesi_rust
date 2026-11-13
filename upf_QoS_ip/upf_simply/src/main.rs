use anyhow::Context as _;
use aya::{maps::PerCpuHashMap, programs::{Xdp, XdpMode}};
use aya::util::nr_cpus;
use clap::Parser;
#[rustfmt::skip]
use log::{warn};
use tokio::{signal, sync::mpsc, time::Instant};
use aya::maps::{RingBuf, HashMap, PerCpuArray, PerCpuValues};
use upf_simply_common::{
    BucketParam, CNT_DECAP, CNT_DROP_FAR, CNT_DROP_QOS, CNT_ENCAP, CNT_ERR, CNT_ERR_INNER_IPV4, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QER, CNT_NO_QFI, FAR_DROP, FAR_FORWARD, Far, GtpPair, NO_QFI, Pdr, Qer, QerState,
};
use std::{net::Ipv4Addr, time::Duration};
use std::process::Command;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface_in: String,
    #[clap(short, long)]
    iface_out: String,
    #[clap(short, long)]
    mbr: u64,
    #[clap(short, long)]
    gbr: u64,

}

// funzione che invoca i comandi TC
fn setup_tc_shaper(iface: &str, mbr: u64, gbr: u64) -> anyhow::Result<()> {
    let mbr_bps = mbr * 1_000_000;
    let gbr_bpr = gbr * 1_000_000;
    println!("Configurazione Traffic Control (HTB Shaper) su {} (MBR: {} Mbps, GBR: {} Mbps)...", iface, mbr, gbr);

    // Formattazione per tc (es. "100000000bit")
    let mbr_str = format!("{}bit", mbr_bps);
    let gbr_str = format!("{}bit", gbr_bpr);
    
    // Assegniamo una rate minima di sussistenza alla coda Gialla (es. 1% dell'MBR) 
    // per rispettare i vincoli di HTB senza rubare banda al GBR.
    let base_yellow_rate = std::cmp::max(mbr_bps / 100, 1000); 
    let excess_str = format!("{}bit", base_yellow_rate);

    let commands = [
        format!("tc qdisc del dev {} root", iface),
        format!("tc qdisc add dev {} root handle 1: htb default 20", iface),
        
        // Classe Padre limitata all'MBR globale
        format!("tc class add dev {} parent 1: classid 1:1 htb rate {} ceil {}", iface, mbr_str, mbr_str),
        
        // Coda Verde (1:10) - Banda Garantita pari al GBR
        format!("tc class add dev {} parent 1:1 classid 1:10 htb rate {} ceil {} burst 15000b", iface, gbr_str, mbr_str),
        
        // Coda Gialla (1:20) - Banda base minima, tetto pari all'MBR
        format!("tc class add dev {} parent 1:1 classid 1:20 htb rate {} ceil {} burst 15000b", iface, excess_str, mbr_str),
        
        // format!("tc qdisc add dev {} parent 1:10 handle 10: fq_codel", iface),
        // format!("tc qdisc add dev {} parent 1:20 handle 20: fq_codel", iface),
        // Sotto-code FIFO rigidissime per forzare il Tail Drop
        // Coda verde limitata a 10 pacchetti
        format!("tc qdisc add dev {} parent 1:10 handle 10: pfifo limit 10", iface),
        // Coda gialla limitata a soli 2 pacchetti (innesco drop istantaneo)
        format!("tc qdisc add dev {} parent 1:20 handle 20: pfifo limit 2", iface),
        format!("tc filter add dev {} protocol ip parent 1:0 prio 1 u32 match ip tos 0x00 0xff flowid 1:10", iface),
        format!("tc filter add dev {} protocol ip parent 1:0 prio 2 u32 match ip tos 0x38 0xff flowid 1:20", iface),
    ];

    for cmd_str in commands.iter() {
        // Separa il comando base dagli argomenti
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        let status = Command::new(parts[0])
            .args(&parts[1..])
            .status();
        
        // Ignoriamo intenzionalmente l'errore del primo comando (pulizia) 
        // nel caso la qdisc non esista ancora.
        if let Ok(st) = status {
            if !st.success() && !cmd_str.contains("del dev") {
                eprintln!("Attenzione: Comando TC fallito: {}", cmd_str);
            }
        } else if !cmd_str.contains("del dev") {
            eprintln!("Errore nell'esecuzione del comando TC: {}", cmd_str);
        }
    }

    println!("Traffic Control configurato con successo.");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let opt = Opt::parse();
    let Opt { iface_in,
            iface_out ,
            mbr ,
            gbr,} = opt;
    env_logger::init();
    
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/upf_simply"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // SAFETY: The logger owns its file descriptor, which stays open and unchanged
            // while the AsyncFd owns it. We only flush the logger, never replace it.
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            }?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let (tx, mut rx) = mpsc::channel::<GtpPair>(100);
    let _manager = tokio::spawn(async move {
        while let Some(hdr_gtp)= rx.recv().await {

            let msg = hdr_gtp.msg_type;
            let teid = hdr_gtp.teid;
            let qfi = hdr_gtp.qfi;
            if qfi != NO_QFI {
                println!("Message Type: {} del TEID: {} con QFI: {}", msg, teid, qfi);
            } else {
                println!("Message Type: {} del TEID: {}", msg, teid);
            }

        }
    });
    // MAPPA UL-PDR
    let mut ul_pdr_map: HashMap<_, u32, Pdr> = HashMap::try_from(ebpf.map_mut("UL_PDR_MAP").unwrap())?;
    ul_pdr_map.insert(9999, Pdr { far_id: 1, outer_hdr_removed: 1, qer_id: 1, _pad: [0;3]}, 0)?;
    ul_pdr_map.insert(8888, Pdr { far_id: 2, outer_hdr_removed: 1, qer_id: 0, _pad: [0;3]}, 0)?;

    // MAPPA DL-PDR
    let mut dl_pdr_map: HashMap<_, u32, Pdr> = HashMap::try_from(ebpf.map_mut("DL_PDR_MAP").unwrap())?;
    dl_pdr_map.insert(Ipv4Addr::new(10, 60, 0, 1).to_bits(), Pdr{ far_id: 3, qer_id: 2, outer_hdr_removed: 0, _pad: [0;3]}, 0)?;
    
    // MAPPA FAR
    let mut far_map: HashMap<_, u32, Far> = HashMap::try_from(ebpf.map_mut("FAR_MAP").unwrap())?;
    far_map.insert(1, Far { action: FAR_FORWARD, outer_hdr_creation: 0, _pad: [0;2], peer_ip: 0, peer_teid: 0, local_ip: 0}, 0)?;
    far_map.insert(2, Far { action: FAR_DROP, outer_hdr_creation: 0, _pad: [0;2], peer_ip: 0, peer_teid: 0, local_ip: 0}, 0)?;
    far_map.insert(3, Far { action: FAR_FORWARD, outer_hdr_creation: 1, _pad: [0; 2],
                                        peer_ip: Ipv4Addr::new(10, 0, 3, 2).to_bits(), peer_teid: 7001,
                                        local_ip: Ipv4Addr::new(10, 0, 3, 1).to_bits() }, 0)?;

    // Calcolo del MBR scalato (Byte/s) per Token Bucket
    // let calc_mbr_scaled = |bits_per_sec: u64| -> u64 {
    //     ((bits_per_sec / 8) << 30) / 1_000_000_000
    // };

    // 1. Calcolo del costo temporale (in nanosecondi) di un byte
    let calc_ns_per_byte_scaled = |bits_per_sec: u64| -> u64 {
        if bits_per_sec == 0 { return 0; } // Gestione dei flussi non-QoS
        let bytes_per_sec = bits_per_sec / 8;
    // Moltiplica 1 secondo (10^9 ns) per 2^30 prima di dividere per i Byte/s
        (1_000_000_000u64 << 30) / bytes_per_sec
    };
    // 2. Calcolo della tolleranza di burst in nanosecondi 
    let calc_burst_tolerance_ns = |bits_per_sec: u64, burst_bytes: u64| -> u64 {
        burst_bytes * calc_ns_per_byte_scaled(bits_per_sec) >> 30
    };
    
    // --- DEFINIZIONE PARAMETRI GLOBALI FLUSSO (Dal Control Plane) ---
    let mbr_bps = mbr * 1_000_000; // in bit/s
    let gbr_bps = gbr * 1_000_000;
    let burst_mbr_bytes= 1500;
    let burst_gbr_bytes = 1500;
    // Calcola quante code hardware/CPU stanno elaborando il traffico
    let num_cpus = nr_cpus().expect("Impossibile determinare il numero di CPU") as u64;
    // --- PARTIZIONE PER-CPU ---
    let mbr_bps_per_cpu = mbr_bps / num_cpus;
    let gbr_bps_per_cpu = gbr_bps / num_cpus;
    let burst_mbr_per_cpu = burst_mbr_bytes / num_cpus;
    let burst_gbr_per_cpu = burst_gbr_bytes / num_cpus;

    // MAPPA QER
    let mut qer_map = HashMap::try_from(ebpf.map_mut("QER_MAP").unwrap())?;
    qer_map.insert(1, Qer {
        qfi: 5, 
        cir_ul: BucketParam { 
            ns_per_byte: calc_ns_per_byte_scaled(gbr_bps_per_cpu), burst_tolerance_ns: calc_burst_tolerance_ns(gbr_bps_per_cpu, burst_gbr_per_cpu) },
        pir_ul: BucketParam { 
            ns_per_byte: calc_ns_per_byte_scaled(mbr_bps_per_cpu), burst_tolerance_ns: calc_burst_tolerance_ns(mbr_bps_per_cpu, burst_mbr_per_cpu) },
        cir_dl: BucketParam { ns_per_byte: 0, burst_tolerance_ns: 0 }, pir_dl: BucketParam { ns_per_byte: 0, burst_tolerance_ns: 0 }}, 0)?;
    
    qer_map.insert(2, Qer {
        qfi: 5, 
        cir_ul: BucketParam { 
            ns_per_byte: calc_ns_per_byte_scaled(gbr_bps_per_cpu), burst_tolerance_ns: calc_burst_tolerance_ns(gbr_bps_per_cpu, burst_gbr_per_cpu) },
        pir_ul: BucketParam { 
            ns_per_byte: calc_ns_per_byte_scaled(mbr_bps_per_cpu), burst_tolerance_ns: calc_burst_tolerance_ns(mbr_bps_per_cpu, burst_mbr_per_cpu) },
        cir_dl: BucketParam { ns_per_byte: 0, burst_tolerance_ns: 0 }, pir_dl: BucketParam { ns_per_byte: 0, burst_tolerance_ns: 0 }}, 0)?;
    // qer_map.insert(1, Qer {qfi: 5, _pad: [0; 7], mbr_dl_scaled: calc_mbr_scaled(400), mbr_ul_scaled: calc_mbr_scaled(400), burst_dl: 100, burst_ul: 100}, 0)?;
    // qer_map.insert(2, Qer {qfi: 5, _pad: [0; 7], mbr_dl_scaled: calc_mbr_scaled(400), mbr_ul_scaled: calc_mbr_scaled(400), burst_dl: 100, burst_ul: 100}, 0)?;


    // MAPP QER-STATE
    let mut qer_state_map: PerCpuHashMap<&mut aya::maps::MapData, u32, QerState> = PerCpuHashMap::try_from(ebpf.map_mut("QER_STATE_MAP").unwrap())?;
    qer_state_map.insert(1, PerCpuValues::try_from((0..num_cpus as usize).map(|_| QerState { tat_cir_dl: 0, tat_pir_dl: 0, tat_cir_ul: 0, tat_pir_ul: 0 }).collect::<Vec<_>>())?, 0)?; // uplink
    qer_state_map.insert(2, PerCpuValues::try_from((0..num_cpus as usize).map(|_| QerState { tat_cir_dl: 0, tat_pir_dl: 0, tat_cir_ul: 0, tat_pir_ul: 0 }).collect::<Vec<_>>())?, 0)?; // downlink
    // qer_state_map.insert(2, QerState { last_update_dl: 0, last_update_ul: 0, tokens_dl: 80 , tokens_ul: 0}, 0)?; // downlink

    
    let program: &mut Xdp = ebpf.program_mut("upf_simply").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface_in, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    // lo shaper va messo sull'interfaccia di USCITA del tunnel
    let _ = setup_tc_shaper(&iface_out, mbr, gbr);

    println!("In ascolto dei pacchetti..... Premi Ctrl +C per uscire");

    let mut ring_buf = RingBuf::try_from(ebpf.take_map("IP_EVENTS").unwrap()).expect("Errore nella ricerca della mappa"); 
    let counters: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("COUNTERS").unwrap())?;
    let qfi_counters: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("QFI_COUNTERS").unwrap())?;
    let mut last_print = Instant::now();
    loop {
        while let Some(item) = ring_buf.next() {
            // println!("Size ricevuta: {}", item.len());
            if item.len() == std::mem::size_of::<GtpPair>() {
                let event  = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const GtpPair) };

                let _ = tx.send(event).await.unwrap();
            }
        }
        
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("");
                println!("Exiting...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if last_print.elapsed() >= Duration::from_secs(5) {
                    println!("---XDP POLICING REPORT----");
                    let _ = print_qfi(&qfi_counters);
                    let _ = print_counters(&counters);

                    println!("\n--- TC SHAPING REPORT ---");
                    let _ = print_tc_stats(&iface_out);
                    println!("-----------");
                    last_print = tokio::time::Instant::now();
                }  
            }
        }
    }
    println!("---FINAL REPORT----");
    let _ = print_qfi(&qfi_counters);
    let _ = print_counters(&counters);
    let _ = print_tc_stats(&iface_out);
    println!("-----------");
    Ok(())
}

fn print_counters(c: &PerCpuArray<aya::maps::MapData, u64>) -> anyhow::Result<()> {
    let voci = [
        (CNT_FORWARD, "forward"),
        (CNT_DECAP, "pkts decapsulati"),
        (CNT_ENCAP, "pkts incapsulati"),
        (CNT_DROP_FAR, "drop (FAR)"),
        (CNT_DROP_QOS, "drop (QoS)"),
        (CNT_NO_PDR, "nessun PDR"),
        (CNT_NO_FAR, "nessun FAR"),
        (CNT_NO_QER, "nessuna QER"),
        (CNT_NO_QFI, "nessuna QFI"),
        (CNT_ERR_INNER_IPV4, "inner pkt not ipv4"),
        (CNT_ERR, "general pkt errors:"),
        
    ];
    for (idx, nome) in voci {
        let per_cpu = c.get(&idx, 0)?; // un valore per CPU
        let totale: u64 = per_cpu.iter().sum();
        println!("{nome:>12}: {totale}");   
    }
    Ok(())
}

fn print_qfi(c: &PerCpuArray<aya::maps::MapData, u64>) -> anyhow::Result<()> {
    for idx in 0..64 {
        let per_cpu = c.get(&idx, 0)?;
        let totale: u64 = per_cpu.iter().sum();
        if totale > 0 {
            println!("QFI: {}: {}", idx, totale)
        }
    }
    Ok(())
}

fn print_tc_stats(iface: &str) {
    if let Ok(output) = std::process::Command::new("tc")
        .args(["-s", "class", "show", "dev", iface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("--- STATISTICHE TC SHAPER (HTB) ---");
        // Filtriamo le righe vuote per mantenere il terminale pulito
        for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
            println!("{}", line);
        }
    } else {
        println!("Impossibile recuperare le statistiche TC per {}", iface);
    }
}
