// Program context types and volatile field access.
//
// UAPI context struct names are LOAD-BEARING: the kernel matches BTF struct
// types BY NAME for freplace/fexit attach compatibility and global-function
// ctx arguments. The structs here carry the exact UAPI name and full layout
// once, instead of per-file hand-declared prefixes.

/// UAPI struct __sk_buff, full layout through hwtstamp (bpf.h). flow_keys
/// and sk are __bpf_md_ptr unions (pointer overlaid with u64), represented
/// as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct __sk_buff {
    pub len: u32,
    pub pkt_type: u32,
    pub mark: u32,
    pub queue_mapping: u32,
    pub protocol: u32,
    pub vlan_present: u32,
    pub vlan_tci: u32,
    pub vlan_proto: u32,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub tc_index: u32,
    pub cb: [u32; 5],
    pub hash: u32,
    pub tc_classid: u32,
    pub data: u32,
    pub data_end: u32,
    pub napi_id: u32,
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub data_meta: u32,
    pub flow_keys: u64,
    pub tstamp: u64,
    pub wire_len: u32,
    pub gso_segs: u32,
    pub sk: u64,
    pub gso_size: u32,
    pub tstamp_type: u8,
    pub hwtstamp: u64,
}

pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_SHOT: i32 = 2;

/// Volatile load of a place: `vload!((*skb).mark)`. Mirrors C's
/// `*(volatile __u32 *)&skb->mark`; keeps LLVM from merging or reordering
/// the access (each ctx load is rewritten individually by the verifier).
#[macro_export]
macro_rules! vload {
    ($place:expr) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!($place)) }
    };
}

/// Volatile narrow load: `vload_as!((*skb).len, u8)` reads the low byte of
/// the field, mirroring `*(volatile __u8 *)&skb->len`.
#[macro_export]
macro_rules! vload_as {
    ($place:expr, $ty:ty) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!($place) as *const $ty) }
    };
}

/// Volatile store: `vstore!((*skb).mark, v)`.
#[macro_export]
macro_rules! vstore {
    ($place:expr, $val:expr) => {
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!($place), $val) }
    };
}
