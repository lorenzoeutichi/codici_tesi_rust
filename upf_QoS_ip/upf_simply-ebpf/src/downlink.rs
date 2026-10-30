use aya_ebpf::{bindings::xdp_action::{XDP_DROP, XDP_PASS}, helpers::generated::{bpf_ktime_get_ns, bpf_xdp_adjust_head}, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use upf_simply_common::{CNT_DROP_FAR, CNT_DROP_QOS, CNT_ENCAP, CNT_ERR, CNT_FORWARD, CNT_NO_FAR, CNT_NO_PDR, CNT_NO_QFI, FAR_FORWARD, Far, NO_QFI};
use crate::{gtp::GtpV1Hdr, maps::{DL_PDR_MAP, FAR_MAP, QER_MAP, QER_STATE_MAP, count, count_qfi}, net::{Ipv4Info, ptr_at_mut}};



#[inline(always)]
pub fn handle(ctx: &XdpContext, eth_hdr: EthHdr, ip: Ipv4Info) -> Result<u32, u32> {

    match unsafe { DL_PDR_MAP.get(&ip.ip_dst)} {
        None => {
            info!(ctx, "nessuna PDR per tale UE ip: {}", ip.ip_dst);
            count(CNT_NO_PDR);
            return Ok(XDP_PASS)
        }

        Some(pdr) => {
            let mut qfi = NO_QFI;
            match unsafe { QER_MAP.get(&pdr.qer_id)} {
                None => count(CNT_NO_QFI),
                Some(qer) => {
                    qfi = qer.qfi;
                    count_qfi(qfi);
                }
            }
            match unsafe {FAR_MAP.get(&pdr.far_id)} {
                None => return Err(CNT_NO_FAR),
                Some(far) => match far.action {
                    FAR_FORWARD => {
                        if police_dl(pdr.qer_id, ip.total_length).is_err() {
                            count(CNT_DROP_QOS);
                            return Ok(XDP_DROP)
                        }
                        if far.outer_hdr_creation == 1 {
                            return encap_dl (ctx, ip.total_length, far, eth_hdr, qfi)
                        }
                        count(CNT_FORWARD);

                    }
                    _ => {
                        count(CNT_DROP_FAR);
                        return Ok(XDP_DROP)
                    }

                }
            }
        }
    }
    Ok(XDP_PASS)
}

#[inline(always)]
fn police_dl(qer_id: u32, tot_length: u16) -> Result<u32, ()> {
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
                unsafe { if  (*ptr_qer).last_update_dl == 0  {
                    (*ptr_qer).last_update_dl = now;
                    }
                    let delta_ns = now - (*ptr_qer).last_update_dl;
                    let nuovi_token = (delta_ns * qer.mbr_dl_scaled) >> 30;
                    (*ptr_qer).tokens_dl += nuovi_token;
                    if (*ptr_qer).tokens_dl > qer.burst_dl {
                        (*ptr_qer).tokens_dl = qer.burst_dl
                    }
                    if (*ptr_qer).tokens_dl >= tot_length as u64 {
                        (*ptr_qer).tokens_dl -= tot_length as u64;
                        (*ptr_qer).last_update_dl = now;
                        return Ok(XDP_PASS)
                    } else {
                        (*ptr_qer).last_update_dl = now;
                        return Err(());
                    }
                }
            }
        }
    }
}

#[inline(always)]
fn encap_dl (ctx: &XdpContext, total_length: u16, far: &Far, eth_hdr_original: EthHdr, qfi: u8) -> Result<u32, u32> {
    let add_hdr: i32 = 44;  // escluso l'eth hdr (ip + udp + gtp-u + ext hdr)
    info!(ctx, "DL Encap: IP total_length estratta = {}", total_length as u32);
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
        (*ip_hdr).set_tos(0, 0);
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

    count(CNT_FORWARD);
    count(CNT_ENCAP);
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