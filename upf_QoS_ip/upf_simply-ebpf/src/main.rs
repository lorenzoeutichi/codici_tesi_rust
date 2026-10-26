#![no_std]
#![no_main]

mod maps;
mod net;
mod gtp;
mod uplink;
// mod downlink;

use aya_ebpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::IpProto, udp::UdpHdr};
use upf_simply_common::CNT_ERR;
use crate::net::ptr_at;

#[xdp]
pub fn upf_simply(ctx: XdpContext) -> u32 {
    match try_upf_simply(&ctx) {
        Ok(ret) => ret,
        Err(counter_idx) => {
            maps::count(counter_idx);
            XDP_PASS
        }
    }
}

#[inline(always)]
fn try_upf_simply(ctx: &XdpContext) -> Result<u32, u32> {
    info!(ctx, "pacchetto catturato");

    let ethhdr: *const EthHdr = ptr_at(ctx, 0).map_err(|_| {
        info!(ctx, "eth: fuori bounds");
        CNT_ERR
    })?;
    
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        info!(ctx, "ethertype non ipv4");
        return Ok(XDP_PASS)
    }
    
    let eth_hdr_copy = unsafe { *ethhdr };
    let ip_info = net::parse_ipv4(ctx)?;

    if ip_info.next_proto == IpProto::Udp {
        let udp_offset = EthHdr::LEN + ip_info.ihl_bytes;
        let udphdr: *const UdpHdr = ptr_at(ctx, udp_offset).map_err(|_| {
            info!(ctx, "udp: fuori bounds");
            CNT_ERR
        })?;
        let dport = unsafe { (*udphdr).dst_port() };
        
        if dport == 2152 {
            info!(ctx, "udp dport = {} => pkt GTP-U", dport);
            let gtp_offset = udp_offset + UdpHdr::LEN;
            let gtp_info = gtp::parse_gtp(ctx, gtp_offset)?;
            return uplink::handle(ctx, eth_hdr_copy, gtp_info);
        }
    }
    Ok(XDP_PASS)
    // downlink::handle(ctx, eth_hdr_copy, ip_info)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";