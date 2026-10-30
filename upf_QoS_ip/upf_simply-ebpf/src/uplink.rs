use aya_ebpf::{bindings::xdp_action::{XDP_DROP, XDP_PASS}, helpers::generated::{bpf_ktime_get_ns, bpf_xdp_adjust_head}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};
use upf_simply_common::{
    CNT_DECAP, CNT_DROP_FAR, CNT_DROP_QOS, CNT_ERR, CNT_ERR_INNER_IPV4, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QFI, FAR_FORWARD, GtpPair, NO_QFI
};
use crate::{gtp::GtpInfo, maps::{FAR_MAP, IP_EVENTS, QER_MAP, QER_STATE_MAP, UL_PDR_MAP, count, count_qfi}, net::{ptr_at, ptr_at_mut}};

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
                    if police_ul(pdr.qer_id, gtp.tot_length).is_err() {
                        count(CNT_DROP_QOS);
                        return Ok(XDP_DROP);
                    }
                    // decapsulazione
                    if pdr.outer_hdr_removed == 1 {
                        return decap_ul(ctx, gtp.payload_offset, eth_hdr_copy)
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
fn police_ul(qer_id: u32, tot_length: u16) -> Result<u32, ()> {
    match unsafe { QER_MAP.get(&qer_id) } {
        None => {
            return Ok(XDP_PASS);
        }
        Some(qer) => match { QER_STATE_MAP.get_ptr_mut(&qer_id)} {
            None => { return Ok(XDP_PASS) }
            Some(ptr_qer) => {
                if ptr_qer.is_null() {
                    return Ok(XDP_PASS)
                }
                let now = unsafe { bpf_ktime_get_ns() };
                unsafe { if  (*ptr_qer).last_update_ul == 0  {
                    (*ptr_qer).last_update_ul = now;
                    }
                    let delta_ns = now - (*ptr_qer).last_update_ul;
                    let nuovi_token = (delta_ns * qer.mbr_ul_scaled) >> 30;
                    (*ptr_qer).tokens_ul += nuovi_token;
                    if (*ptr_qer).tokens_ul > qer.burst_ul {
                        (*ptr_qer).tokens_ul = qer.burst_ul
                    }
                    if (*ptr_qer).tokens_ul >= tot_length as u64 {
                        (*ptr_qer).tokens_ul -= tot_length as u64;
                        (*ptr_qer).last_update_ul = now;
                        return Ok(XDP_PASS)
                    } else {
                        (*ptr_qer).last_update_ul = now;
                        return Err(());
                    }
                }
            }
        }
    }
}


#[inline(always)]
fn decap_ul(ctx: &XdpContext, offset: usize, eth_hdr_copy: EthHdr) -> Result<u32, u32> {
    let inner_ip: *const Ipv4Hdr = ptr_at(ctx, offset).map_err(|_| {
        info!(ctx, "inner ip: fuori bounds");
        CNT_ERR_INNER_IPV4
    })?;
    if unsafe { (*inner_ip).version() } != 4 {
        info!(ctx, "inner ip: versione non 4");
        return Err(CNT_ERR_INNER_IPV4);
    }

    let delta: i32 = (offset - EthHdr::LEN) as i32; // byte di pkt da togliere (dall'outer ip al gtp-u)
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta).is_negative() } {
        return Err(CNT_ERR);
    }
    
    let eth_header_mut: *mut EthHdr = ptr_at_mut(ctx, 0)?; // in realtà sono 14 byte di GTP-U
    unsafe { *eth_header_mut = eth_hdr_copy; } 
    
    count(CNT_DECAP);
    count(CNT_FORWARD);
    Ok(XDP_PASS)
}