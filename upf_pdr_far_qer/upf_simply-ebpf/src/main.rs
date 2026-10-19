#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action::{self, XDP_PASS}, macros::{map, xdp}, maps::{HashMap, PerCpuArray, RingBuf}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, udp::UdpHdr};
use upf_simply_common::{
    Far, GtpPair, Pdr, CNT_DROP_FAR, CNT_FORWARD, CNT_MAX, CNT_NO_FAR, CNT_NO_PDR, FAR_FORWARD,
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

#[inline(always)]
fn count(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
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
    info!(&ctx, "udp dport = {}", dport);
    if dport == 2152 {
        // PKT GTP
        let mut off = length_eth_ip + UdpHdr::LEN ;
        let gtp: *const GtpV1Hdr = ptr_at(&ctx, off)?;

        if unsafe { (*gtp).flags & 0xF0 == 0x30 } {

            off += 8;
            let mut qfi = 0xFF;
            if unsafe { (*gtp).flags & 0x07 != 0x00 } {
                // 4 byte opzionali: seq (2), N-PDU (1), next ext type (1)
                let opt: [u8; 4] = unsafe { *ptr_at::<[u8; 4]>(&ctx, off)? };
                off += 4;
                let mut next_type = if unsafe { (*gtp).flags & 0x04 != 0x00 } { opt[3] } else { 0 };
                info!(&ctx, "offset: {}, qfi: {} --> next type: {}", off, qfi, next_type);
                
                for _ in 0..3 {
                    if next_type == 0 {
                        break;
                    }
                    let w: [u8; 8] = unsafe { *ptr_at::<[u8; 8]>(&ctx, off)? };
                    let len = w[0] as usize;
                    if len == 0 || len > 2 {
                        return Ok(XDP_PASS);
                    }
                    if next_type == 0x85 {
                        qfi = w[2] & 0x3F;
                    }
                    next_type = if len == 1 { w[3] } else { w[7] };
                    off += len * 4;
                }           
                info!(&ctx, "offset: {}, qfi: {} --> next type: {}", off, qfi, next_type);
                if next_type != 0 {
                    return Ok(XDP_PASS); // catena più lunga del limite
                }
            }
            info!(&ctx, "offset: {}, qfi: {}", off, qfi);

            let teid = unsafe {u32::from_be((*gtp).teid)};
            if let Some(mut entry) = IP_EVENTS.reserve::<GtpPair>(0) {
                unsafe {
                    core::ptr::write(
                        entry.as_mut_ptr(), 
                        GtpPair { msg_type: (*gtp).msg_type, teid: teid }
                    );
                }
                entry.submit(0);
                info!(&ctx, "Message Type e TEID estratto dal pacchetto GTP-U");
            }
            // controllo PDR/FAR
            if unsafe {(*gtp).msg_type}  != 255 {
                   return Ok(xdp_action::XDP_PASS); 
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
