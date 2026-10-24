use aya_ebpf::{bindings::xdp_action::{XDP_DROP, XDP_PASS}, helpers::generated::bpf_xdp_adjust_head, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};
use upf_simply_common::{
    GtpPair, CNT_FORWARD, CNT_DECAP, CNT_NO_QFI, CNT_NO_PDR, CNT_NO_FAR, CNT_DROP_FAR, CNT_ERR, FAR_FORWARD, NO_QFI
};
use crate::{gtp::GtpInfo, maps::{count, count_qfi, FAR_MAP, IP_EVENTS, UL_PDR_MAP}, net::{ptr_at_mut, ptr_at}};

#[inline(always)]
pub fn handle(ctx: &XdpContext, eth_hdr_copy: EthHdr, gtp: GtpInfo) -> Result<u32, u32> {
    if let Some(mut entry) = IP_EVENTS.reserve::<GtpPair>(0) {
        unsafe {
            core::ptr::write(
                entry.as_mut_ptr(), 
                GtpPair { msg_type: gtp.msg_type, qfi: gtp.qfi, _pad: [0, 0], teid: gtp.teid }
            );
        }
        entry.submit(0);
        info!(ctx, "Message Type, TEID e QFI estratto dal pacchetto GTP-U");
    }

    // contatori PDR/FAR/QER e QoS
    if gtp.msg_type  != 255 {
        return Ok(XDP_PASS); 
    }
    if gtp.qfi != NO_QFI {
        count_qfi(gtp.qfi);
    } else {
        count(CNT_NO_QFI);
    }
    match unsafe { UL_PDR_MAP.get(gtp.teid) } {
        None => {
            return Err(CNT_NO_PDR); 
        }
        Some(pdr) => match unsafe { FAR_MAP.get(pdr.far_id) } {
            None => {
                return Err(CNT_NO_FAR); 
            }
            Some(far) => match far.action {
                FAR_FORWARD => {
                    // decapsulazione
                    if pdr.outer_hdr_removed == 1 {
                        return decap_ul(&ctx, gtp.payload_offset, eth_hdr_copy)
                    }
                    count(CNT_FORWARD);  
                }
            // FAR_DROP e qualsiasi valore sconosciuto
                _ => {
                    count(CNT_DROP_FAR);
                    return Ok(XDP_DROP)
                }
            },
        },
    }

    Ok(XDP_PASS)
}

#[inline(always)]
fn decap_ul(ctx: &XdpContext, offset: usize, eth_hdr_copy: EthHdr) -> Result<u32, u32> {
    let inner_ip: *const Ipv4Hdr = ptr_at(ctx, offset)?;
    if unsafe { (*inner_ip).version() } != 4 {
        return Err(CNT_ERR);
    }

    let delta: i32 = (offset - EthHdr::LEN) as i32; 
    
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta).is_negative() } {
        return Err(CNT_ERR);
    }
    
    let eth_header_mut: *mut EthHdr = ptr_at_mut(ctx, 0)?; 
    unsafe { *eth_header_mut = eth_hdr_copy; } 
    
    count(CNT_DECAP);
    count(CNT_FORWARD);
    Ok(XDP_PASS)
}