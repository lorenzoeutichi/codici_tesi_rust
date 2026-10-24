use aya_ebpf::{macros::map, maps::{HashMap, PerCpuArray, RingBuf}};
use upf_simply_common::{Far, Pdr, Qer, CNT_MAX, N_CONT};

#[map]
pub(crate) static IP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
#[map]
pub(crate) static UL_PDR_MAP: HashMap<u32, Pdr> = HashMap::with_max_entries(1024, 0); // chiave TEID
#[map]
pub(crate) static FAR_MAP: HashMap<u32, Far> = HashMap::with_max_entries(1024, 0); //chiave FAR_ID
#[map]
pub(crate) static QER_MAP: HashMap<u32, Qer> = HashMap::with_max_entries(1024, 0); // chiave QER_ID
#[map]
pub(crate) static DL_PDR_MAP: HashMap<u32, Pdr> = HashMap::with_max_entries(1024, 0); // chiave UE IP
#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(CNT_MAX, 0);
#[map]
static QFI_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_CONT, 0); // indice QFI

#[inline(always)]
pub(crate) fn count(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
}

#[inline(always)]
pub(crate) fn count_qfi(idx: u8) {
    if let Some(c) = QFI_COUNTERS.get_ptr_mut(idx.into()) {
        unsafe { *c += 1 };
    }
}