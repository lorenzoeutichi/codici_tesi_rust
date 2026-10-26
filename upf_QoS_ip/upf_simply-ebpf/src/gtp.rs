use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use upf_simply_common::{NO_QFI, CNT_ERR};
use crate::net::ptr_at;

#[repr(C, packed)]
// struttura necessaria per lavorare con l'header GTP-U
pub struct GtpV1Hdr {
    pub flags: u8,
    pub msg_type: u8,
    pub length: u16,
    pub teid: u32,
}

#[derive(Clone, Copy)]
pub struct GtpInfo {
    pub msg_type: u8,
    pub teid: u32,
    pub qfi: u8,
    pub payload_offset: usize,
}

#[inline(always)]
pub fn parse_gtp(ctx: &XdpContext, start_offset: usize) -> Result<GtpInfo, u32> {
    let gtp: *const GtpV1Hdr = ptr_at(ctx, start_offset)?;
    let flags = unsafe { (*gtp).flags };
    
    if flags & 0xF0 != 0x30 { 
        return Err(CNT_ERR);
    }
    // => PKT GTP-U V1
    let mut off_byte = start_offset + 8; // 8 byte: lunghezza minima hdr gtp-u
    let mut qfi = NO_QFI; // valore per mappare assenza QFI

    if flags & 0x07 != 0x00 { // flag E o S o PN attivi
        // 4 byte opzionali dell'header base GTP-U: seq num (2), N-PDU (1), next ext type (1)
        off_byte += 4;
        if flags & 0x04 != 0x00 { // controllo flag E (Extension Header) attivo
            let mut pos = off_byte - 1; // byte type del primo next extension header
            for _ in 0..3 {
                let w: *const [u8; 4] = ptr_at(ctx, pos)?; // ext_hdr_type e i primi 3 byte dell'ext_hdr
                let next_ext_hdr_type = unsafe { (*w)[0] };
                let (ext_hdr_len, qfi_byte) = unsafe { ((*w)[1] as usize, (*w)[3]) };
                
                if next_ext_hdr_type == 0 { break; } // = 0: nessun ext hdr successivo
                if ext_hdr_len == 0 { return Err(CNT_ERR); }
                if next_ext_hdr_type == 0x85 { // PDU Session Container
                    qfi = qfi_byte & 0x3F; // prendo gli ultimi 6 bit meno significativi (relativi al secondo byte)
                }
                pos += ext_hdr_len * 4; // 4 byte: lunghezza dell' ext hdr
            }
            // dopo l'ultimo header letto, il tipo del successivo deve essere 0x00
            let w: *const [u8; 2] = ptr_at(ctx, pos)?;
            if unsafe { (*w)[0] } != 0x00 { // catena più lunga del limite
                return Err(CNT_ERR);
            }
            off_byte = pos + 1; // primo byte del payload (utile per decapsulare)
        }
    }

    info!(ctx, "offset: {}, qfi: {}", off_byte as u32, qfi);

    Ok(GtpInfo {
        msg_type: unsafe { (*gtp).msg_type },
        teid: u32::from_be(unsafe { (*gtp).teid }),
        qfi: qfi,
        payload_offset: off_byte,
    })
}