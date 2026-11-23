use anyhow::{Context as _};
use aya::{maps::PerCpuHashMap, programs::{Xdp, XdpMode}};
use aya::util::nr_cpus;
use clap::Parser;
#[rustfmt::skip]
use log::{warn};
use tokio::{net::UdpSocket, signal, sync::mpsc, time::Instant};
use aya::maps::{RingBuf, HashMap, PerCpuArray};
use upf_simply_common::{
    CNT_DECAP, CNT_DROP_FAR, CNT_DROP_QOS, CNT_ENCAP, CNT_ERR, CNT_ERR_INNER_IPV4, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QER, CNT_NO_QFI, CNT_NON_QOS, Far, GtpPair, IFACE_ROLE_DN, IFACE_ROLE_RAN, NO_QFI, Pdr, Qer, QerState,
};
use std::{net::Ipv4Addr, time::Duration};
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;

mod control;
use crate::control::{ControlState, FarAction::{Drop, Forward}, apply_command, run_control_plane};


#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "eth0")]
    iface_ran: String,
    #[clap(long)]
    iface_dn: String,
    #[clap(long)]
    mbr_dl: u64,
    #[clap(long)]
    gbr_dl: u64,
    #[clap(long)]
    mbr_ul: u64,
    #[clap(long)]
    gbr_ul: u64,
    #[clap(long, default_value_t = 10)]
    non_qos_rate: u64,
    #[clap(long, default_value_t = 14)]
    strip_bytes_ul: u32,
    #[clap(long, default_value_t = 58)]
    strip_bytes_dl: u32,   // byte da non contare nell'HTB: 14 in UL, 58 in DL
    #[clap(short, long, default_value = "127.0.0.1:8805")]
    cp_addr: String,

}

fn get_ifindex(iface: &str) -> anyhow::Result<u32> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("impossibile leggere {path}: interfaccia '{iface}' inesistente?"))?;
    return raw.trim()
        .parse::<u32>()
        .with_context(|| format!("ifindex non valido per '{iface}': {raw:?}"))
}

// funzione che invoca i comandi TC
fn setup_tc_shaper(iface: &str, mbr: u64, gbr: u64, non_qos_rate: u64, strip_bytes: u32) -> anyhow::Result<()> {
    let mbr_bps = mbr * 1_000_000;
    let gbr_bps = gbr * 1_000_000;
    let non_qos_rate_bps = non_qos_rate * 1_000_000;
    println!("Configurazione Traffic Control (HTB Shaper) su {} (MBR: {} Mbps, GBR: {} Mbps, Non-GBR: {} Mbps)...", iface, mbr, gbr, non_qos_rate);

    // Formattazione per tc (es. "100000000bit")
    let mbr_str = format!("{}bit", mbr_bps);
    let gbr_str = format!("{}bit", gbr_bps);
    let non_gbr_str = format!("{}bit", non_qos_rate_bps);
    
    // Assegniamo una rate minima di sussistenza alla coda Gialla (es. 1% dell'MBR) 
    // per rispettare i vincoli di HTB senza rubare banda al GBR.
    let base_yellow_rate = std::cmp::max(mbr_bps / 100, 1000);
    let excess_str = format!("{}bit", base_yellow_rate);

    let commands = [
        format!("tc qdisc del dev {} root", iface),
        if strip_bytes > 0 {
            format!("tc qdisc add dev {} root handle 1: stab overhead -{} linklayer ethernet htb default 30",
            iface, strip_bytes)
        } else {
            format!("tc qdisc add dev {} root handle 1: htb default 30", iface)
        },
        
        // QoS Shaper
        // Classe Padre limitata all'MBR globale
        format!("tc class add dev {} parent 1: classid 1:1 htb rate {} ceil {} burst 15000b cburst 15000b", iface, mbr_str, mbr_str),
        // Coda Verde (1:10) - Banda Garantita pari al GBR
        format!("tc class add dev {} parent 1:1 classid 1:10 htb rate {} ceil {} burst 15000b cburst 15000b prio 0", iface, gbr_str, mbr_str),
        // Coda Gialla (1:20) - Banda base minima, tetto pari all'MBR
        format!("tc class add dev {} parent 1:1 classid 1:20 htb rate {} ceil {} burst 15000b cburst 15000b prio 1", iface, excess_str, mbr_str),

        // Non-QoS Shaper
        // Coda Non-QoS (1:30) - Best Effort 
        format!("tc class add dev {} parent 1: classid 1:30 htb rate {} ceil {} burst 15000b cburst 15000b prio 2", iface, non_gbr_str, non_gbr_str),
        
        // Classi foglia fq_codel per assicurare che il traffico consentito venga consegnato con la massima equità e la minima latenza possibile.
        format!("tc qdisc add dev {} parent 1:10 handle 10: fq_codel", iface),
        format!("tc qdisc add dev {} parent 1:20 handle 20: fq_codel", iface),
        format!("tc qdisc add dev {} parent 1:30 handle 30: fq_codel", iface),
        // Sotto-code FIFO rigidissime per forzare il Tail Drop
        // format!("tc qdisc add dev {} parent 1:10 handle 10: pfifo limit 100", iface),
        // format!("tc qdisc add dev {} parent 1:20 handle 20: pfifo limit 100", iface),

        format!("tc filter add dev {} protocol ip parent 1:0 prio 1 u32 match ip tos 0x28 0xfc flowid 1:10", iface),
        format!("tc filter add dev {} protocol ip parent 1:0 prio 2 u32 match ip tos 0x38 0xfc flowid 1:20", iface),
        format!("tc filter add dev {} protocol ip parent 1:0 prio 3 u32 match ip tos 0x00 0xfc flowid 1:30", iface),
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
    let Opt { iface_ran,
            iface_dn ,
            mbr_dl ,
            gbr_dl,
            mbr_ul,
            gbr_ul,
            non_qos_rate,
            strip_bytes_dl,
            strip_bytes_ul,
            cp_addr,} = opt;
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
                //println!("Message Type: {} del TEID: {} con QFI: {}", msg, teid, qfi);
            } else {
                // println!("Message Type: {} del TEID: {}", msg, teid);
            }

        }
    });

    let qer_state_map: Arc<Mutex<PerCpuHashMap<_, u32, QerState>>> =
        Arc::new(Mutex::new(PerCpuHashMap::try_from(ebpf.take_map("QER_STATE_MAP").unwrap())?));
    let qer_map: Arc<Mutex<HashMap<_, u32, Qer>>> = Arc::new(Mutex::new(HashMap::try_from(ebpf.take_map("QER_MAP").unwrap())?));
    let far_map: Arc<Mutex<HashMap<_, u32, Far>>> = Arc::new(Mutex::new(HashMap::try_from(ebpf.take_map("FAR_MAP").unwrap())?));
    let ul_pdr_map: Arc<Mutex<HashMap<_, u32, Pdr>>> = Arc::new(Mutex::new(HashMap::try_from(ebpf.take_map("UL_PDR_MAP").unwrap())?));
    let dl_pdr_map: Arc<Mutex<HashMap<_, u32, Pdr>>> = Arc::new(Mutex::new(HashMap::try_from(ebpf.take_map("DL_PDR_MAP").unwrap())?));
    
    let num_cpus = nr_cpus().expect("Impossibile determinare il numero di CPU") as u64; // Calcola quante code hardware/CPU stanno elaborando il traffico
    let cpu_div = 1;
    let list_maps = ControlState {
        ul_pdr_map,
        dl_pdr_map,
        far_map,
        qer_map,
        qer_state_map,
        num_cpus,
        cpu_div,

    };
    
    // REGOLE UPLINK
    apply_command(&list_maps, control::ControlCommand::AddUplink { teid: 9999, far_id: 1, far_action: Forward, outer_hdr_removed: true,
                                                                            qos: Some(control::QosParams {
                                                                                qer_id: 1, qfi: 5, gbr_mbps: gbr_ul, mbr_mbps: mbr_ul, burst_bytes: 15_000 }) })?;
    apply_command(&list_maps, control::ControlCommand::AddUplink { teid: 8888, far_id: 2, far_action: Drop, outer_hdr_removed: true,
                                                                            qos: None })?;
    // REGOLA IN DOWNLINK
    apply_command(&list_maps, control::ControlCommand::AddDownlink { ue_ip: Ipv4Addr::new(10, 60, 0, 1), far_id: 3, far_action: Forward,
                                                                                peer_ip: Ipv4Addr::new(10, 0, 3, 2), peer_teid: 7001,
                                                                                local_ip: Ipv4Addr::new(10, 0, 3, 1), outer_hdr_creation: true, 
                                                                                qos: Some(control::QosParams { 
                                                                                    qer_id: 2, qfi: 5, gbr_mbps: gbr_dl, mbr_mbps: mbr_dl, burst_bytes: 15_000 }) })?;

    let socket = UdpSocket::bind(cp_addr).await?;
    let list_map_cp = list_maps.clone();
    let _control_plane = tokio::spawn(async move {
        run_control_plane(socket, list_map_cp).await
    });

    let ifindex_ran = get_ifindex(&iface_ran)?;
    let ifindex_dn = get_ifindex(&iface_dn)?;
    anyhow::ensure!(
        ifindex_ran != ifindex_dn,
        "iface-n3 e iface-n6 devono essere due interfacce diverse"
    );

    let mut iface_role_map: HashMap<_, u32, u8> = HashMap::try_from(
        ebpf.map_mut("IFACE_ROLE_MAP")
            .context("mappa IFACE_ROLE_MAP non trovata")?,
    )?;
    iface_role_map.insert(ifindex_ran, IFACE_ROLE_RAN, 0)?;
    iface_role_map.insert(ifindex_dn, IFACE_ROLE_DN, 0)?;

    println!(
        "Ruoli interfacce: {} (ifindex {}) -> RAN | {} (ifindex {}) -> DATA NETWORK",
        iface_ran, ifindex_ran, iface_dn, ifindex_dn
    );

    let program: &mut Xdp = ebpf.program_mut("upf_simply").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface_ran, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;
    program.attach(&iface_dn, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    // lo shaper va messo sull'interfaccia di USCITA del tunnel
    let _ = setup_tc_shaper(&iface_dn, mbr_ul, gbr_ul, non_qos_rate, strip_bytes_ul);
    let _ = setup_tc_shaper(&iface_ran, mbr_dl, gbr_dl, non_qos_rate, strip_bytes_dl);

    println!("In ascolto dei pacchetti..... Premi Ctrl +C per uscire");

    let mut ring_buf = RingBuf::try_from(ebpf.take_map("IP_EVENTS").unwrap()).expect("Errore nella ricerca della mappa"); 
    let counters_dl: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("COUNTERS_DL").unwrap())?;
    let counters_ul: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("COUNTERS_UL").unwrap())?;
    let qfi_counters_dl: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("QFI_COUNTERS_DL").unwrap())?;
    let qfi_counters_ul: PerCpuArray<aya::maps::MapData, u64> = PerCpuArray::try_from(ebpf.take_map("QFI_COUNTERS_UL").unwrap())?;
    let mut last_print = Instant::now();
    let mut last_print_tc = Instant::now();
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
                    println!("\n---XDP POLICING REPORT----");
                    let _ = print_qfi(&qfi_counters_ul, &qfi_counters_dl);
                    let _ = print_counters(&counters_ul, &counters_dl);
                    last_print = tokio::time::Instant::now();
                    
                    if last_print_tc.elapsed() >= Duration::from_secs(30) {
                    println!("\n--- TC UPLINK SHAPING REPORT ---");
                    let _ = print_tc_stats(&iface_dn);
                    println!("\n--- TC DOWNLINK SHAPING REPORT ---");
                    let _ = print_tc_stats(&iface_ran); 
                    last_print_tc = tokio::time::Instant::now();
                    }
                    println!("-----------");
                }  
                  
            }
        }
    }
    println!("\n---FINAL REPORT----");
    println!("\n---XDP POLICING REPORT----");
    let _ = print_qfi(&qfi_counters_ul, &qfi_counters_dl);
    let _ = print_counters(&counters_ul, &counters_dl);
    println!("\n--- TC UPLINK SHAPING REPORT ---");
    let _ = print_tc_stats(&iface_dn);
    println!("\n--- TC DOWNLINK SHAPING REPORT ---");
    let _ = print_tc_stats(&iface_ran);
    println!("-----------");
    Ok(())
}

fn sum_per_cpu(map: &PerCpuArray<aya::maps::MapData, u64>, idx: u32) -> anyhow::Result<u64> {
    let per_cpu = map.get(&idx, 0)?;
    Ok(per_cpu.iter().sum())
}

fn print_counters(
    ul: &PerCpuArray<aya::maps::MapData, u64>,
    dl: &PerCpuArray<aya::maps::MapData, u64>,
) -> anyhow::Result<()> {
    let voci = [
        (CNT_FORWARD, "forward"),
        (CNT_DECAP, "pkts decapsulati"),
        (CNT_ENCAP, "pkts incapsulati"),
        (CNT_NON_QOS, "pkts Non-QoS"),
        (CNT_DROP_FAR, "drop (FAR)"),
        (CNT_DROP_QOS, "drop (QoS)"),
        (CNT_NO_PDR, "nessun PDR"),
        (CNT_NO_FAR, "nessun FAR"),
        (CNT_NO_QER, "nessuna QER"),
        (CNT_NO_QFI, "nessuna QFI"),
        (CNT_ERR_INNER_IPV4, "inner pkt not ipv4"),
        (CNT_ERR, "general pkt errors"),
    ];

    let sep = "-".repeat(59);
    println!("{sep}");
    println!(
        "{:<20} | {:>10} | {:>10} | {:>10}",
        "Contatore", "Uplink", "Downlink", "Totale"
    );
    println!("{sep}");

    for (idx, nome) in voci {
        let val_ul = sum_per_cpu(ul, idx)?;
        let val_dl = sum_per_cpu(dl, idx)?;
        let tot = val_ul + val_dl;
        println!("{nome:<20} | {val_ul:>10} | {val_dl:>10} | {tot:>10}");
    }

    println!("{sep}");
    Ok(())
}

fn print_qfi(
    qfi_ul: &PerCpuArray<aya::maps::MapData, u64>,
    qfi_dl: &PerCpuArray<aya::maps::MapData, u64>,
) -> anyhow::Result<()> {
    let sep = "-".repeat(59);
    let mut printed_header = false;

    for idx in 0..64 {
        let val_ul = sum_per_cpu(qfi_ul, idx)?;
        let val_dl = sum_per_cpu(qfi_dl, idx)?;
        if val_ul == 0 && val_dl == 0 {
            continue;
        }

        if !printed_header {
            println!("{sep}");
            println!(
                "{:<20} | {:>10} | {:>10} | {:>10}",
                "QFI", "Uplink", "Downlink", "Totale"
            );
            println!("{sep}");
            printed_header = true;
        }

        let tot = val_ul + val_dl;
        println!("{idx:<20} | {val_ul:>10} | {val_dl:>10} | {tot:>10}");
    }

    if printed_header {
        println!("{sep}");
    } else {
        println!("(nessun traffico QFI)");
    }
    Ok(())
}

fn print_tc_stats(iface: &str) {
    if let Ok(output) = std::process::Command::new("tc")
        .args(["-s", "class", "show", "dev", iface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Filtriamo le righe vuote per mantenere il terminale pulito
        for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
            println!("{}", line);
        }
    } else {
        println!("Impossibile recuperare le statistiche TC per {}", iface);
    }
}