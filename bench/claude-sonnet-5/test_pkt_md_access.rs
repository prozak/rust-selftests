#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pkt_md_access.c
//
// TEST_FIELD(TYPE, FIELD, MASK) reads skb->FIELD once as TYPE (a narrow,
// possibly truncated volatile read starting at the field's address) and
// once as the full u32 (also volatile), and checks the narrow read equals
// the full read masked. This only matches C's little-endian TEST_FIELD
// variant, which reads the truncated value directly at &skb->FIELD; the
// UML/x86-64 target here is little-endian.

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
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    flow_keys: u64,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    sk: u64,
    gso_size: u32,
    tstamp_type: u8,
    hwtstamp: u64,
}

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_md_access(skb: *const __sk_buff) -> i32 {
    macro_rules! test_field {
        ($ty:ty, $field:ident, $mask:expr) => {{
            let full_ptr = unsafe { core::ptr::addr_of!((*skb).$field) } as *const u32;
            let full = unsafe { core::ptr::read_volatile(full_ptr) };
            let narrow_ptr = full_ptr as *const $ty;
            let narrow = unsafe { core::ptr::read_volatile(narrow_ptr) };
            if narrow as u32 != (full & $mask) {
                return TC_ACT_SHOT;
            }
        }};
    }

    test_field!(u8, len, 0xFF);
    test_field!(u16, len, 0xFFFF);
    test_field!(u32, len, 0xFFFFFFFF);
    test_field!(u16, protocol, 0xFFFF);
    test_field!(u32, protocol, 0xFFFFFFFF);
    test_field!(u8, hash, 0xFF);
    test_field!(u16, hash, 0xFFFF);
    test_field!(u32, hash, 0xFFFFFFFF);

    TC_ACT_OK
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
