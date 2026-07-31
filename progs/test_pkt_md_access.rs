#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pkt_md_access.c
// (little-endian variant).
//
// A TC (SCHED_CLS) program whose whole point is narrow context loads: each
// __sk_buff u32 field is read back as u8, u16, and u32 and cross-checked.
// Volatile reads keep LLVM from merging the accesses, mirroring the C
// `*(volatile TYPE *)&skb->FIELD` pattern; the verifier rewrites each
// narrow ctx load individually.

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

// UAPI struct __sk_buff prefix — offsets are ABI, only fields up to `hash`
// are needed here.
#[allow(non_camel_case_types)]
#[repr(C)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
}

macro_rules! test_field {
    ($field:expr, $ty:ty, $mask:expr) => {{
        let p = core::ptr::addr_of!($field);
        let tmp = unsafe { core::ptr::read_volatile(p as *const $ty) };
        let full = unsafe { core::ptr::read_volatile(p) };
        if tmp as u32 != (full & $mask) {
            return TC_ACT_SHOT;
        }
    }};
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_md_access(skb: *const __sk_buff) -> i32 {
    let skb = unsafe { &*skb };
    test_field!(skb.len, u8, 0xFF);
    test_field!(skb.len, u16, 0xFFFF);
    test_field!(skb.len, u32, 0xFFFF_FFFF);
    test_field!(skb.protocol, u16, 0xFFFF);
    test_field!(skb.protocol, u32, 0xFFFF_FFFF);
    test_field!(skb.hash, u8, 0xFF);
    test_field!(skb.hash, u16, 0xFFFF);
    test_field!(skb.hash, u32, 0xFFFF_FFFF);
    TC_ACT_OK
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
