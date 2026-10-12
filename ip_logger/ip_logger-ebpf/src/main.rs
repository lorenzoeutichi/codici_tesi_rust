#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, programs::XdpContext, maps::RingBuf};
use aya_log_ebpf::info;
use core::mem;
use network_types::{self, eth::{EthHdr, EtherType}, ip::Ipv4Hdr};
use ip_logger_common::IpPair;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Definizione formale della mappa RING BUFFER
#[map]
pub static IP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Controllo matematico dei limiti di memoria, codice obbligatorio
#[inline(always)] // indica di "incollare" la seguente funzione nel punto in cui è stata chiamata
fn prt_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {

    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    } else {
        Ok((start + offset) as *const T)
    }
}

#[xdp]
pub fn ip_logger(ctx: XdpContext) -> u32 { 
    // tale funzione delega la logica principale del processing del pkt 
    match try_ip_logger(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ip_logger(ctx: XdpContext) -> Result<u32, ()> {

    let ethhdr: *const EthHdr = prt_at(&ctx, 0)?; // creo puntatore di tipo EthHdr to inzio del pkt
    match unsafe {
        (*ethhdr).ether_type() // controllo che il pkt sia Ipv4
    } {
        Ok(EtherType::Ipv4) => {
            // creo puntatore Ipv4 to inizio header ipv4
            let ipv4hdr : *const Ipv4Hdr = prt_at(&ctx, 14)?; // EthHdr::LEN

            // Estrazione dei bit grezzi riguardanti IP sorgente e destinazione
            let src_addr_raw = u32::from_ne_bytes(unsafe {
                (*ipv4hdr).src_addr
            });
            let dst_addr_raw = u32::from_ne_bytes(unsafe {
                (*ipv4hdr).dst_addr
            });

            // Reserve: tenta di allocare spazio di tipo IpPair all'interno del ring buffer, ritorna eventuale ingresso del buf
            if let Some(mut entry) = IP_EVENTS.reserve::<IpPair>(0) {
                unsafe {
                    // scrittura degli indirizzi all'interno del ring buf tramite il puntatore "restituito"
                    core::ptr::write(
                        entry.as_mut_ptr(), 
                        IpPair {
                            src: src_addr_raw,
                            dst: dst_addr_raw,
                        }
                    );
                }
                // submit: obbligatoria dopo la reserve, salva le modifiche al buf e informa di ciò l'user space
                entry.submit(0);
                // invia log informativo all'user associato all'attuale contesto (pkt corrente)
                info!(&ctx, "Indirizzo Ipv4 sorgente e destinaione estratto dal pacchetto");
            } else {
                // se la reserve fallisce (ring pieno) si scarta il pacchetto
                return Ok(xdp_action::XDP_PASS);
            }
        },
        _ => return Ok(xdp_action::XDP_PASS),
    }

    Ok(xdp_action::XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
