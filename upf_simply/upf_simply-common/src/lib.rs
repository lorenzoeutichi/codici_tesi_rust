#![no_std]

#[repr(C)] // impone al compilatore Rust di allineare la memoria come farebbe un compilatore C
#[derive(Clone, Copy, Debug)]
pub struct GtpPair {
    pub msg_type: u8,
    pub teid: u32,
}