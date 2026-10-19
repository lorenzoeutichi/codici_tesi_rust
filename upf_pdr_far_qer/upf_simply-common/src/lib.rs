#![no_std]

#[repr(C)] // impone al compilatore Rust di allineare la memoria come farebbe un compilatore C
#[derive(Clone, Copy, Debug)]
pub struct GtpPair {
    pub msg_type: u8,
    pub teid: u32,
    
}

#[repr(C)] 
#[derive(Clone, Copy, Debug)]
pub struct Pdr {
    pub far_id: u32,
    // pub qer_id: u32,
    // pub precedence: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Far {
    pub action: u8,
}

pub const FAR_DROP: u8 = 0;
pub const FAR_FORWARD: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Qer {
    pub qfi: u8,
    pub mbr_ul: u32,
    pub mbr_dl: u32,
}

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
pub const CNT_MAX: u32 = 4;

