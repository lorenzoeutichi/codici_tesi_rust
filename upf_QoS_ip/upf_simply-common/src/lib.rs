#![no_std]

#[repr(C)] // impone al compilatore Rust di allineare la memoria come farebbe un compilatore C
#[derive(Clone, Copy, Debug)]
pub struct GtpPair {
    pub msg_type: u8,
    pub qfi: u8,
    pub _pad: [u8; 2],
    pub teid: u32,
    
}

pub const NO_QFI: u8 = 0xFF; // valore per mappare QFI non presente
pub const N_CONT: u32 = 64;

#[repr(C)] 
#[derive(Clone, Copy, Debug)]
pub struct Pdr {
    pub far_id: u32,
    pub qer_id: u32,
    pub outer_hdr_removed: u8, // // sorta di flag per rimozione hdr esterno
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Far {
    pub action: u8,
    pub outer_hdr_creation: u8, // sorta di flag per creazione hdr esterno
    pub _pad: [u8; 2],
    // campi per l'incapsulamento
    pub peer_ip: u32,
    pub peer_teid: u32,
    pub local_ip: u32,

}

pub const FAR_DROP: u8 = 0;
pub const FAR_FORWARD: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Qer {
    pub qfi: u8,
    pub _pad: [u8; 7],
    pub mbr_ul_scaled: u64,      // Maximum Bit Rate scalato (in byte) per l'Uplink (pre-calcolato dall'userspace)
    pub mbr_dl_scaled: u64,      // MBR scalato per il Downlink
    pub burst_ul: u64,    // Burst Size in byte per l'Uplink
    pub burst_dl: u64,    // Burst Size in byte per il Downlink 
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QerState {
    pub last_update_ul: u64, // Timestamp in nanosecondi
    pub last_update_dl: u64,
    pub tokens_ul: u64,   // Token disponibili per l'Uplink (in Byte)
    pub tokens_dl: u64,   // Token disponibili per il Downlink (in Byte)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QerState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Pdr {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Far {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Qer {}

pub const CNT_FORWARD: u32 = 0;
pub const CNT_DROP_FAR: u32 = 1;
pub const CNT_NO_PDR: u32 = 2;
pub const CNT_NO_FAR: u32 = 3;
pub const CNT_NO_QFI: u32 = 4;
pub const CNT_DECAP: u32 = 5;
pub const CNT_ENCAP: u32 = 6;
pub const CNT_ERR_INNER_IPV4: u32 = 7;
pub const CNT_ERR: u32 = 8; // racchiude tutti gli errori generici sui pkts
pub const CNT_DROP_QOS: u32 = 9;
pub const CNT_MAX: u32 = 10;

