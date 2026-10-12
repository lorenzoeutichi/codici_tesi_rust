#![no_std]

#[repr(C)] // impone al compilatore Rust di allineare la memoria come farebbe un compilatore C
pub struct IpPair {
    pub src: u32,
    pub dst: u32,
}