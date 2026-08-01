#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pkt_md_access.c
//
// A TC (SCHED_CLS) program run via bpf_prog_test_run_opts. For each of
// skb->len, skb->protocol and skb->hash it does a narrow (1/2/4-byte) ctx
// load and checks it against the full 4-byte load masked down to the same
// width — exercising the verifier's narrow ctx-access rewriting. Any
// mismatch returns TC_ACT_SHOT so the userspace test sees a nonzero retval.
//
// This is a little-endian-only build (bpfel), so only the
// __ORDER_LITTLE_ENDIAN__ arm of the C TEST_FIELD macro is translated: the
// narrow load sits at offset 0 of the field.
//
// Both loads are volatile, exactly as in C, so LLVM cannot merge the narrow
// load into the wide one (which would make the comparison vacuous).

// UAPI struct __sk_buff. The name must match the C one exactly: the kernel
// matches BTF struct types by name when checking freplace/fexit attach
// compatibility (prog_tests/trace_ext.c replaces this program, and
// fexit_bpf2bpf's test_target_no_callees attaches fexit to it).
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
extern "C" fn test_pkt_md_access(skb: *mut __sk_buff) -> i32 {
    // TEST_FIELD(TYPE, FIELD, MASK): compare the TYPE-wide load of FIELD
    // against the u32-wide load masked with MASK. C promotes the narrow tmp
    // to unsigned int for the comparison, hence the `as u32`.
    macro_rules! test_field {
        ($ty:ty, $field:ident, $mask:expr) => {{
            let p = unsafe { core::ptr::addr_of!((*skb).$field) };
            let tmp = unsafe { core::ptr::read_volatile(p as *const $ty) } as u32;
            let full = unsafe { core::ptr::read_volatile(p) };
            if tmp != (full & $mask) {
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
