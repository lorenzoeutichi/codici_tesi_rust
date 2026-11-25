use aya_ebpf::{bindings::xdp_action::{XDP_DROP, XDP_PASS}, helpers::generated::{bpf_ktime_get_ns, bpf_xdp_adjust_head}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use upf_simply_common::{CNT_DROP_FAR, CNT_DROP_QOS, CNT_ENCAP, CNT_ERR, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QER, CNT_NO_QFI, CNT_NON_QOS, DSCP_BE, FAR_FORWARD, Far};
use crate::{gtp::GtpV1Hdr, maps::{DL_PDR_MAP, FAR_MAP, QER_MAP, QER_STATE_MAP, count_dl, count_qfi_dl}, net::{EsitoPolicing::{self, Green, NonQos, Red, Yellow}, Ipv4Info, ptr_at_mut}};



#[inline(always)]
pub fn handle(ctx: &XdpContext, eth_hdr: EthHdr, ip: Ipv4Info) -> Result<u32, u32> {

    match unsafe { DL_PDR_MAP.get(&ip.ip_dst)} {
        None => {
            info!(ctx, "nessuna PDR per tale UE ip: {}", ip.ip_dst);
            count_dl(CNT_NO_PDR);
            return Ok(XDP_PASS)
        }
        Some(pdr) => {
            let mut qfi = 0;
            if pdr.qer_id != 0 {
                match unsafe { QER_MAP.get(&pdr.qer_id)} {
                    None => count_dl(CNT_NO_QFI),
                    Some(qer) => {
                        qfi = qer.qfi;
                        count_qfi_dl(qfi);
                    }
                }
            }
            match unsafe {FAR_MAP.get(&pdr.far_id)} {
                None => return Err(CNT_NO_FAR),
                Some(far) => match far.action {
                    FAR_FORWARD => {
                        
                        let dscp = match police_dl(pdr.qer_id, ip.total_length) {
                            Red => {
                                count_dl(CNT_DROP_QOS);
                                return Ok(XDP_DROP)
                            }
                            Green(d) => d,
                            Yellow(d) => d,
                            NonQos(d) => d,
                        };
                        if far.outer_hdr_creation == 1 {
                            return encap_dl (ctx, ip.total_length, far, eth_hdr, qfi, dscp)
                        }
                        count_dl(CNT_FORWARD);
                    }
                    _ => {
                        count_dl(CNT_DROP_FAR);
                        return Ok(XDP_DROP)
                    }

                }
            }
        }
    }
    Ok(XDP_PASS)
}

#[inline(always)]
fn police_dl(qer_id: u32, ip_tot_length: u16) -> EsitoPolicing {
    if qer_id == 0 {
        count_dl(CNT_NON_QOS);
        return NonQos(DSCP_BE)
    }
    match unsafe { QER_MAP.get(&qer_id)} {
        None => {
            count_dl(CNT_NO_QER);
            return NonQos(DSCP_BE)
        }
        Some(qer) => {
            if qer.pir_dl.ns_per_byte == 0 {
                count_dl(CNT_NON_QOS);
                return NonQos(qer.dscp_green)
            }
            match QER_STATE_MAP.get_ptr_mut(&qer_id) {
                None => { 
                    count_dl(CNT_NO_QER);
                    return NonQos(DSCP_BE)
                }
                Some(ptr_qer) => {
                    if ptr_qer.is_null() {
                        return NonQos(DSCP_BE)
                    }
                    
                    let now = unsafe {bpf_ktime_get_ns() };
                    let cost_ip_pkt_p = (ip_tot_length as u64 * qer.pir_dl.ns_per_byte) >> 30;
                    let cost_ip_pkt_c = (ip_tot_length as u64 * qer.cir_dl.ns_per_byte) >> 30;
                    
                    // Accesso sicuro e diretto: questa memoria è esclusiva della CPU corrente
                    // Peak
                    let current_tat_pir = unsafe { (*ptr_qer).tat_pir_dl };
                    let time_base_pir = core::cmp::max(current_tat_pir, now);
                    let new_tat_pir = time_base_pir + cost_ip_pkt_p;
                    // Committed
                    let current_tat_cir = unsafe { (*ptr_qer).tat_cir_dl };
                    let time_base_cir = core::cmp::max(current_tat_cir, now);
                    let new_tat_cir = time_base_cir + cost_ip_pkt_c;

                    // Condizione ROSSO
                    if new_tat_pir - now > qer.pir_dl.burst_tolerance_ns {
                        return Red;
                    }
                    // Condizione GIALLO
                    else if new_tat_cir - now > qer.cir_dl.burst_tolerance_ns {
                        unsafe { (*ptr_qer).tat_pir_dl = new_tat_pir; }
                        return Yellow(qer.dscp_yellow);
                    }
                    // Condizione VERDE
                    else {
                        unsafe { (*ptr_qer).tat_pir_dl = new_tat_pir; }
                        unsafe { (*ptr_qer).tat_cir_dl = new_tat_cir; }
                        return Green(qer.dscp_green);
                    }
                }
            }
        }
    }
}


#[inline(always)]
fn encap_dl (ctx: &XdpContext, total_length: u16, far: &Far, eth_hdr_original: EthHdr, qfi: u8, dscp: u8) -> Result<u32, u32> {
    let add_hdr: i32 = 44;  // escluso l'eth hdr (ip + udp + gtp-u + ext hdr)
    info!(ctx, "DL Encap: IP total length estratta = {}", total_length as u32);
    if total_length + (add_hdr as u16) > 1500 {
        info!(ctx, "MTU standard (1500 byte) superato");
        return Err(CNT_ERR);
    }

    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -add_hdr) != 0 } {
        return Err(CNT_ERR);
    }
    // aggiunta hdr ethernet
    let eth_hdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;
    unsafe { (*eth_hdr) = eth_hdr_original};
    // aggiunta hdr IPv4 esterno
    let ip_hdr: *mut Ipv4Hdr = ptr_at_mut(ctx, EthHdr::LEN)?;
    unsafe {
        // le funzioni set convertono automaticamente in Network Order 
        (*ip_hdr).set_vihl(4, 20);
        (*ip_hdr).set_tos(dscp, 0);
        (*ip_hdr).set_tot_len(total_length + add_hdr as u16);
        (*ip_hdr).set_id(0);
        (*ip_hdr).ttl = 64;
        (*ip_hdr).set_frags(0, 0);
        (*ip_hdr).set_proto(network_types::ip::IpProto::Udp);
        (*ip_hdr).set_checksum(0);
        (*ip_hdr).src_addr = far.local_ip.to_be_bytes();
        (*ip_hdr).dst_addr = far.peer_ip.to_be_bytes();
    }
    // aggiunta hdr UDP
    let udp_hdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    unsafe {
        (*udp_hdr).set_src_port(2152);
        (*udp_hdr).set_dst_port(2152);
        (*udp_hdr).set_len(total_length + 16 + 8);
        (*udp_hdr).set_checksum(0);
    }
    // aggiunta hdr GTP-U
    let gtp_hdr: *mut GtpV1Hdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;
    unsafe {
        (*gtp_hdr).flags = 0x34; //flag E attivo
        (*gtp_hdr).msg_type = 255;
        (*gtp_hdr).length = (total_length + 8).to_be() ;
        (*gtp_hdr).teid = far.peer_teid.to_be();
    }
    // aggiunta ext hdr
    let ext_hdr: *mut [u8; 8] = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 8)?;
    unsafe {
        (*ext_hdr)[0] = 0x00; // sequence number
        (*ext_hdr)[1] = 0x00; // sequence number
        (*ext_hdr)[2] = 0x00; // N-PDU
        (*ext_hdr)[3] = 0x85; // next ext hdr type
        (*ext_hdr)[4] = 0x01; // lunghezza ext hdr
        (*ext_hdr)[5] = 0x00; // pdu type (0: dl)
        (*ext_hdr)[6] = qfi & 0x3F; // scrivo il qfi negli ultimi 6 bit
        (*ext_hdr)[7] = 0x00;
    }

    // calcolo dell' ip hdr checksum
    unsafe {(*ip_hdr).set_checksum(checksum_ipv4hdr(ip_hdr)) }; 
    info!(ctx, "pkt ip incapsulato correttamente in un GTP-U");

    count_dl(CNT_FORWARD);
    count_dl(CNT_ENCAP);
    Ok(XDP_PASS)
}

fn checksum_ipv4hdr (ip_hdr: *const Ipv4Hdr) -> u16 {
    let mut conta: u32 = 0;
    let vec_ip_hdr =  ip_hdr as *const [u16; 10];
    for i in 0..10 {
        conta += unsafe { (*vec_ip_hdr)[i] as u32};
    }
    // somma dei vari riporti nei primi 16 bit
    conta = (conta >> 16) + (conta & 0xFFFF); // tale somma potrebbe creare un ulteriore riporto
    conta = (conta >> 16) + (conta & 0xFFFF); 
    return u16::to_be(!(conta as u16)); //dato che la somma lavora con valori già in Network Order
}