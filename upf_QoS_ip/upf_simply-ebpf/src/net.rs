use core::mem;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::{IpProto, Ipv4Hdr}};
use upf_simply_common::CNT_ERR;

#[derive(Clone, Copy)]
pub struct Ipv4Info {
    pub ihl_bytes: usize,
    pub next_proto: IpProto,
    pub ip_dst: u32,
    pub total_length: u16,
    
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(CNT_ERR);
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(CNT_ERR);
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub fn parse_ipv4(ctx: &XdpContext) -> Result<Ipv4Info, u32> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN).map_err(|_| {
        info!(ctx, "ip: fuori bounds");
        CNT_ERR
    })?;
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    info!(ctx, "ihl bytes = {}", ihl as u32);
    if ihl < Ipv4Hdr::LEN {
        info!(&ctx, "ihl troppo piccolo");
        return Err(CNT_ERR);
    }
    
    let next_proto = match unsafe { (*ipv4hdr).proto() } {
        Ok(proto) => proto,
        Err(_) => return Err(CNT_ERR),
    };
    let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let length_pkt = u16::from_be(unsafe {(*ipv4hdr).tot_len() });
    
    Ok(Ipv4Info {
        ihl_bytes: ihl,
        next_proto,
        ip_dst: dst,
        total_length: length_pkt
    })
}