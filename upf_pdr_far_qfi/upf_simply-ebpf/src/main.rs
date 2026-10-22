#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action::{self, XDP_PASS}, macros::{map, xdp}, maps::{HashMap, PerCpuArray, RingBuf}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, udp::UdpHdr};
use upf_simply_common::{
    CNT_DROP_FAR, CNT_FORWARD, CNT_MAX, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QFI, FAR_FORWARD, Far, GtpPair, N_CONT, NO_QFI, Pdr,
};

#[repr(C, packed)]
// struttura necessaria per lavorare con l'header GTP-U
struct GtpV1Hdr {
    flags: u8,
    msg_type: u8,
    length: u16,
    teid: u32,
}

#[xdp]
pub fn upf_simply(ctx: XdpContext) -> u32 {
    match try_upf_simply(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[map]
pub static IP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
#[map]
static PDR_MAP: HashMap<u32, Pdr> = HashMap::with_max_entries(1024, 0); // chiave TEID
#[map]
static FAR_MAP: HashMap<u32, Far> = HashMap::with_max_entries(1024, 0); // chiave FAR_ID
// #[map]
// static QER_MAP: HashMap<u32, Qer> = HashMap::with_max_entries(1024, 0); // chiave QER_ID
#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(CNT_MAX, 0);
#[map]
static QFI_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_CONT, 0); // indice QFI

#[inline(always)]
fn count(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
}
#[inline(always)]
fn count_qfi(idx: u8) {
    if let Some(c) = QFI_COUNTERS.get_ptr_mut(idx.into()) {
        unsafe { *c += 1 };
    }
}

#[inline(always)]
fn ptr_at<T> (ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {

    let start = ctx.data();
    let end = ctx.data_end();
    
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)    
}

fn try_upf_simply(ctx: XdpContext) -> Result<u32, ()> {

    info!(&ctx, "pacchetto catturato");
    //PKT ETHERNET
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).map_err(|_| {
        info!(&ctx, "eth: fuori bounds");
    })?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => {
            info!(&ctx, "ethertype non ipv4");
            return Ok(xdp_action::XDP_PASS);
        }
    }
    // PKT IP e UDP
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).map_err(|_| {
        info!(&ctx, "ip: fuori bounds");
    })?;
    match unsafe { (*ipv4hdr).proto() } {
        Ok(IpProto::Udp) => {}
        _ => {
            info!(&ctx, "ip proto non udp");
            return Ok(xdp_action::XDP_PASS);
        }
    }
    let ihl = (unsafe { (*ipv4hdr).ihl() } as usize);
    info!(&ctx, "ihl bytes = {}", ihl as u32);
    if ihl < Ipv4Hdr::LEN {
        info!(&ctx, "ihl troppo piccolo");
        return Ok(xdp_action::XDP_PASS);
    }
    let length_eth_ip = EthHdr::LEN + ihl;
    let udphdr: *const UdpHdr = ptr_at(&ctx, length_eth_ip).map_err(|_| {
        info!(&ctx, "udp: fuori bounds");
    })?;
    let dport = unsafe { (*udphdr).dst_port() };
    info!(&ctx, "udp dport = {} => pkt GTP-U", dport);
    if dport == 2152 {
        // PKT GTP
        info!(&ctx, "=> pkt GTP-U");
        let mut off_byte = length_eth_ip + UdpHdr::LEN ;
        let gtp: *const GtpV1Hdr = ptr_at(&ctx, off_byte)?;

        if unsafe { (*gtp).flags & 0xF0 == 0x30 } { // PKT GTP v1

            off_byte += 8;
            let mut qfi = NO_QFI; // valore per mappare assenza QFI
            if unsafe { (*gtp).flags & 0x07 != 0x00 } { // flag E o S o PN attivi
                // 4 byte opzionali dell'header base GTP-U: seq num (2), N-PDU (1), next ext type (1)
                off_byte += 4;
                if unsafe { (*gtp).flags & 0x04 != 0x00 } { // controllo flag E (Extension Header) attivo
                    let mut pos = off_byte - 1;     // byte type del primo next extension header
                    for _ in 0..3 {
                        let w: *const [u8; 4] = ptr_at(&ctx, pos)?; // ext_hdr_type e i primi 3 byte dell'ext_hdr 
                        let next_ext_hdr_type = unsafe { (*w)[0] };
                        let (ext_hdr_len, qfi_byte) = unsafe { ((*w)[1] as usize, (*w)[3]) };
                        if next_ext_hdr_type == 0 {
                            break;
                        }
                        if ext_hdr_len == 0 {
                            return Ok(XDP_PASS);
                        }
                        if next_ext_hdr_type == 0x85 { // PDU Session Container
                            qfi = qfi_byte & 0x3F; // prendo gli ultimi 6 bit meno significativi
                        }
                        pos += ext_hdr_len * 4;
                    }
                    // dopo l'ultimo header letto, il tipo del successivo deve essere 0x00
                    let w: *const [u8; 2] = ptr_at(&ctx, pos)?;
                    if unsafe { (*w)[0] } != 0x00 { // catena più lunga del limite
                        return Ok(XDP_PASS);    
                    }
                    off_byte = pos + 1; // primo byte del payload (utile per decapsulare)
                }        
            }
            info!(&ctx, "offset: {}, qfi: {}", off_byte, qfi);
            
            let teid = unsafe {u32::from_be((*gtp).teid)};
            if let Some(mut entry) = IP_EVENTS.reserve::<GtpPair>(0) {
                unsafe {
                    core::ptr::write(
                        entry.as_mut_ptr(), 
                        GtpPair { msg_type: (*gtp).msg_type,  teid: teid, qfi: qfi, _pad: [0, 0]}
                    );
                }
                entry.submit(0);
                info!(&ctx, "Message Type e TEID estratto dal pacchetto GTP-U");
            }
            // contatori PDR/FAR e QFI
            if unsafe {(*gtp).msg_type}  != 255 {
                   return Ok(xdp_action::XDP_PASS); 
            }
            if qfi != NO_QFI {
                count_qfi(qfi);
            } else {
                count(CNT_NO_QFI);
            }
            match unsafe { PDR_MAP.get(teid) } {
                None => {
                    count(CNT_NO_PDR);
                    return Ok(xdp_action::XDP_PASS);
                }
                Some(pdr) => match unsafe { FAR_MAP.get(pdr.far_id) } {
                    None => {
                        count(CNT_NO_FAR);
                        return Ok(xdp_action::XDP_PASS);
                    }
                    Some(far) => match far.action {
                        FAR_FORWARD => {
                            count(CNT_FORWARD);
                            return Ok(xdp_action::XDP_PASS);
                        }
                    // FAR_DROP e qualsiasi valore sconosciuto
                        _ => {
                        count(CNT_DROP_FAR);
                        return Ok(xdp_action::XDP_DROP);
                        }
                    },
                },
            }
 
        }
    }
    Ok(xdp_action::XDP_PASS)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";