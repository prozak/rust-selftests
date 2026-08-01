#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_skb_ctx.c
//
// A TC (SCHED_CLS) program exercising BPF_PROG_TEST_RUN's ctx_in/ctx_out
// plumbing: prog_tests/skb_ctx.c hands in a fully populated struct __sk_buff,
// and this program validates the fields it must see and bumps the writable
// ones so userspace can check the values that come back out.
//
// Every context access goes through read_volatile/write_volatile so LLVM
// cannot merge or reorder the individual ctx loads/stores — the verifier
// rewrites each one separately, exactly as it does for the clang build of the
// __pragma_loop_unroll_full loop.

// UAPI struct __sk_buff — full layout (the kernel matches ctx types by name,
// and offsets are ABI). `flow_keys`/`sk` are __bpf_md_ptr unions: 8 bytes,
// 8-byte aligned.
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
    _pad: [u8; 3],
    hwtstamp: u64,
}

macro_rules! ctx_read {
    ($place:expr) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!($place)) }
    };
}

macro_rules! ctx_write {
    ($place:expr, $val:expr) => {
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!($place), $val) }
    };
}

// One unrolled iteration of the C `for (i = 0; i < 5; i++)` body.
macro_rules! check_cb {
    ($skb:expr, $i:expr) => {{
        let v: u32 = ctx_read!((*$skb).cb[$i]);
        if v != ($i as u32) + 1 {
            return 1;
        }
        ctx_write!((*$skb).cb[$i], v.wrapping_add(1));
    }};
}

macro_rules! check_eq {
    ($skb:expr, $field:ident, $val:expr) => {{
        let v = ctx_read!((*$skb).$field);
        if v != $val {
            return 1;
        }
    }};
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn process(skb: *mut __sk_buff) -> i32 {
    check_cb!(skb, 0);
    check_cb!(skb, 1);
    check_cb!(skb, 2);
    check_cb!(skb, 3);
    check_cb!(skb, 4);

    let priority: u32 = ctx_read!((*skb).priority);
    ctx_write!((*skb).priority, priority.wrapping_add(1));
    let tstamp: u64 = ctx_read!((*skb).tstamp);
    ctx_write!((*skb).tstamp, tstamp.wrapping_add(1));
    let mark: u32 = ctx_read!((*skb).mark);
    ctx_write!((*skb).mark, mark.wrapping_add(1));

    check_eq!(skb, wire_len, 100u32);
    check_eq!(skb, gso_segs, 8u32);
    check_eq!(skb, gso_size, 10u32);
    check_eq!(skb, ingress_ifindex, 11u32);
    check_eq!(skb, ifindex, 1u32);
    check_eq!(skb, hwtstamp, 11u64);

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
