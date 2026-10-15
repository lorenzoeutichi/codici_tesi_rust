#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::RingBuf, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, udp::UdpHdr};
use upf_simply_common::GtpPair;

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

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type()} {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    match unsafe {(*ipv4hdr).proto()} {
        Ok(IpProto::Udp) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ihl = (unsafe { (*ipv4hdr).ihl() } as usize) * 4;
    if ihl < Ipv4Hdr::LEN {
        return Ok(xdp_action::XDP_PASS);
    }
    let length_eth_ip = EthHdr::LEN + ihl;

    let udphdr: *const UdpHdr = ptr_at(&ctx, length_eth_ip)?;
    if unsafe {(*udphdr).dst_port() == 2152} {
        let gtp: *const GtpV1Hdr = ptr_at(&ctx, length_eth_ip + UdpHdr::LEN)?;
        if unsafe { (*gtp).flags & 0xF0 == 0x30 } {
            if let Some(mut entry) = IP_EVENTS.reserve::<GtpPair>(0) {
                unsafe {
                    core::ptr::write(
                        entry.as_mut_ptr(), 
                        GtpPair { msg_type: (*gtp).msg_type, teid: (*gtp).teid }
                    );
                }
                entry.submit(0);
                info!(&ctx, "Message Type e TEID estratto dal pacchetto GTP-U");
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
