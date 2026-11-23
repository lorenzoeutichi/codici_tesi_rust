use aya_ebpf::{bindings::xdp_action::{XDP_DROP, XDP_PASS}, helpers::generated::{bpf_ktime_get_ns, bpf_xdp_adjust_head}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};
use upf_simply_common::{
    CNT_DECAP, CNT_DROP_FAR, CNT_DROP_QOS, CNT_ERR, CNT_ERR_INNER_IPV4, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QER, CNT_NO_QFI, CNT_NON_QOS, DSCP_AF11, DSCP_AF13, DSCP_BE, FAR_FORWARD, GtpPair, NO_QFI
};
use crate::{gtp::GtpInfo, maps::{FAR_MAP, IP_EVENTS, QER_MAP, QER_STATE_MAP, UL_PDR_MAP, count_qfi_ul, count_ul}, net::{EsitoPolicing::{self, Green, NonQos, Red, Yellow}, ptr_at_mut}};


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
        count_qfi_ul(gtp.qfi);
    } else {
        count_ul(CNT_NO_QFI);
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
                    let inner_ip_pkt: *mut Ipv4Hdr = ptr_at_mut(ctx, gtp.payload_offset).map_err(|_| CNT_ERR_INNER_IPV4)?;
                    if unsafe { (*inner_ip_pkt).version() } != 4 {
                        info!(ctx, "inner ip: versione non 4");
                        return Err(CNT_ERR_INNER_IPV4);
                    }
                    info!(ctx, "lunghezza pkt ip interno: {}", unsafe { (*inner_ip_pkt).tot_len()});
                    let dscp = match police_ul(pdr.qer_id, unsafe {(*inner_ip_pkt).tot_len()} ) { // gli devo passa la lunghezza del pkt ip 
                        Red => {
                            count_ul(CNT_DROP_QOS);
                            return Ok(XDP_DROP);
                        }
                        Green => DSCP_AF11,
                        Yellow => DSCP_AF13,
                        NonQos => DSCP_BE
                        
                    };
                    mark_dscp_checksum_ipv4hdr(inner_ip_pkt, dscp);

                    // decapsulazione
                    if pdr.outer_hdr_removed == 1 {
                        return decap_ul(ctx, gtp.payload_offset, eth_hdr_copy)
                    }
                    count_ul(CNT_FORWARD);  
                }
            // FAR_DROP e qualsiasi valore sconosciuto
                _ => {
                    count_ul(CNT_DROP_FAR);
                    return Ok(XDP_DROP)
                }
            },
        },
    }

    Ok(XDP_PASS)
}

#[inline(always)]
fn police_ul(qer_id: u32, ip_tot_length: u16) -> EsitoPolicing {
    if qer_id == 0 {
        count_ul(CNT_NON_QOS);
        return NonQos;
    }
    match unsafe { QER_MAP.get(&qer_id)} {
        None => {
            count_ul(CNT_NO_QER);
            return NonQos
        }
        Some(qer) => {
            if qer.pir_ul.ns_per_byte == 0 {
                count_ul(CNT_NON_QOS);
                return NonQos
            }
            match QER_STATE_MAP.get_ptr_mut(&qer_id) {
                None => { 
                    count_ul(CNT_NO_QER);
                    return NonQos }
                Some(ptr_qer) => {
                    if ptr_qer.is_null() {
                        return NonQos;
                    }
                    let now = unsafe {bpf_ktime_get_ns() };
                    let cost_ip_pkt_p = (ip_tot_length as u64 * qer.pir_ul.ns_per_byte) >> 30; // calcolo costo di picco
                    let cost_ip_pkt_c = (ip_tot_length as u64 * qer.cir_ul.ns_per_byte) >> 30; // calcolo costo garantito

                    // Accesso sicuro e diretto: questa memoria è esclusiva della CPU corrente
                    //Peak
                    let current_tat_pir = unsafe { (*ptr_qer).tat_pir_ul };
                    let time_base_pir = core::cmp::max(current_tat_pir, now);
                    let new_tat_pir = time_base_pir + cost_ip_pkt_p;
                    // Committed
                    let current_tat_cir = unsafe { (*ptr_qer).tat_cir_ul };
                    let time_base_cir = core::cmp::max(current_tat_cir, now);
                    let new_tat_cir = time_base_cir + cost_ip_pkt_c;

                    // condizione ROSSO 
                    if new_tat_pir - now > qer.pir_ul.burst_tolerance_ns {
                        return Red; // Supera il burst: Drop QoS
                    }
                    // Condizione GIALLO
                    else if new_tat_cir - now > qer.cir_ul.burst_tolerance_ns {
                        // superamento del CIR, ma non del PIR
                        unsafe { (*ptr_qer).tat_pir_ul = new_tat_pir; }                        
                        return Yellow
                    } 
                    // Condizione VERDE
                    else {
                        unsafe { (*ptr_qer).tat_pir_ul = new_tat_pir; }
                        unsafe { (*ptr_qer).tat_cir_ul = new_tat_cir; }
                        return Green
                    }                    
                }
            }
        }
    }
}

#[inline(always)]
fn mark_dscp_checksum_ipv4hdr (ip_hdr: *mut Ipv4Hdr, dscp: u8) {
    unsafe { if (*ip_hdr).dscp() == dscp {
        return
    }}
    // set dscp
    unsafe {
        (*ip_hdr).set_tos(dscp, (*ip_hdr).ecn());
        (*ip_hdr).set_checksum(0);
    }
    //checksum
    let mut conta: u32 = 0;
    let vec_ip_hdr =  ip_hdr as *const [u16; 10];
    for i in 0..10 {
        conta += unsafe { (*vec_ip_hdr)[i] as u32};
    }
    // somma dei vari riporti nei primi 16 bit
    conta = (conta >> 16) + (conta & 0xFFFF); // tale somma potrebbe creare un ulteriore riporto
    conta = (conta >> 16) + (conta & 0xFFFF);
    let checksum = u16::to_be(!(conta as u16)); //dato che la somma lavora con valori già in Network Order

    unsafe { (*ip_hdr).set_checksum(checksum); }
}


#[inline(always)]
fn decap_ul(ctx: &XdpContext, offset: usize, eth_hdr_copy: EthHdr) -> Result<u32, u32> {
    
    let delta: i32 = (offset - EthHdr::LEN) as i32; // byte di pkt da togliere (dall'outer ip al gtp-u)
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta).is_negative() } {
        return Err(CNT_ERR);
    }
    
    let eth_header_mut: *mut EthHdr = ptr_at_mut(ctx, 0)?; // in realtà sono 14 byte di GTP-U
    unsafe { *eth_header_mut = eth_hdr_copy; } 
    
    count_ul(CNT_DECAP);
    count_ul(CNT_FORWARD);
    Ok(XDP_PASS)
}

