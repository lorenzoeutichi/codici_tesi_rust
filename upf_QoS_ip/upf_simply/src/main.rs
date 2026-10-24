use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
#[rustfmt::skip]
use log::{warn};
use tokio::{signal, sync::mpsc, time::Instant};
use aya::maps::{RingBuf, HashMap, PerCpuArray};
use upf_simply_common::{
    CNT_DECAP, CNT_DROP_FAR, CNT_ENCAP, CNT_ERR, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QFI, FAR_DROP, FAR_FORWARD, Far, GtpPair, NO_QFI, Pdr, Qer,
};
use std::{net::Ipv4Addr, time::Duration};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let opt = Opt::parse();
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
    ul_pdr_map.insert(9999, Pdr { far_id: 1, outer_hdr_removed: 1, qer_id: 0, _pad: [0;3]}, 0)?;
    ul_pdr_map.insert(8888, Pdr { far_id: 2, outer_hdr_removed: 1, qer_id: 0, _pad: [0;3]}, 0)?;

    // MAPPA DL-PDR
    let mut dl_pdr_map: HashMap<_, u32, Pdr> = HashMap::try_from(ebpf.map_mut("DL_PDR_MAP").unwrap())?;
    dl_pdr_map.insert(Ipv4Addr::new(10, 60, 0, 1).to_bits(), Pdr{ far_id: 3, qer_id: 1, outer_hdr_removed: 0, _pad: [0;3]}, 0)?;
    
    // MAPPA FAR
    let mut far_map: HashMap<_, u32, Far> = HashMap::try_from(ebpf.map_mut("FAR_MAP").unwrap())?;
    far_map.insert(1, Far { action: FAR_FORWARD, outer_hdr_creation: 0, _pad: [0;2], peer_ip: 0, peer_teid: 0, local_ip: 0}, 0)?;
    far_map.insert(2, Far { action: FAR_DROP, outer_hdr_creation: 0, _pad: [0;2], peer_ip: 0, peer_teid: 0, local_ip: 0}, 0)?;
    far_map.insert(3, Far { action: FAR_FORWARD, outer_hdr_creation: 1, _pad: [0; 2],
                                        peer_ip: Ipv4Addr::new(10, 0, 3, 2).to_bits(), peer_teid: 7001,
                                        local_ip: Ipv4Addr::new(10, 0, 3, 1).to_bits() }, 0)?;

    // MAPPA QER
    let mut qer_map = HashMap::try_from(ebpf.map_mut("QER_MAP").unwrap())?;
    qer_map.insert(1, Qer {qfi: 5, _pad: [0; 3], mbr_dl: 0, mbr_ul: 0}, 0)?;

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("upf_simply").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::Skb)
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

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
                    println!("---NEW REPORT----");
                    let _ = print_qfi(&qfi_counters);
                    let _ = print_counters(&counters);
                    println!("-----------");
                    last_print = tokio::time::Instant::now();
                }  
            }
        }
    }
    
    let _ = print_qfi(&qfi_counters);
    let _ = print_counters(&counters);
    Ok(())
}

fn print_counters(c: &PerCpuArray<aya::maps::MapData, u64>) -> anyhow::Result<()> {
    let voci = [
        (CNT_FORWARD, "forward"),
        (CNT_DROP_FAR, "drop (FAR)"),
        (CNT_NO_PDR, "nessun PDR"),
        (CNT_NO_FAR, "nessun FAR"),
        (CNT_NO_QFI, "nessuna QFI"),
        (CNT_DECAP, "pkts decapsulati"),
        (CNT_ENCAP, "pkts incapsulati"),
        (CNT_ERR, "inner pkt non valido"),
        
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
