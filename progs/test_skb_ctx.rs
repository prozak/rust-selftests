#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_skb_ctx.c
//
// A TC (SCHED_CLS) program run via bpf_prog_test_run_opts with a caller
// supplied ctx: it verifies cb[]/wire_len/gso_*/ifindex/hwtstamp hold the
// values the userspace test seeded, and increments cb[i], priority, tstamp
// and mark so the test can observe them in ctx_out.
//
// cb[] is accessed with constant indices only (the C loop is fully
// unrolled) — the verifier rejects variable-offset ctx access. Volatile
// accesses keep each ctx load/store separate and 4/8-byte sized.

// UAPI struct __sk_buff, full layout up to hwtstamp. flow_keys and sk are
// __bpf_md_ptr unions (pointer overlaid with u64), represented as u64.
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

#[link_section = "tc"]
#[no_mangle]
extern "C" fn process(skb: *mut __sk_buff) -> i32 {
    macro_rules! cb_step {
        ($i:expr) => {{
            let p = unsafe { core::ptr::addr_of_mut!((*skb).cb[$i]) };
            let v = unsafe { core::ptr::read_volatile(p) };
            if v != $i as u32 + 1 {
                return 1;
            }
            unsafe { core::ptr::write_volatile(p, v.wrapping_add(1)) };
        }};
    }
    macro_rules! bump {
        ($field:ident) => {{
            let p = unsafe { core::ptr::addr_of_mut!((*skb).$field) };
            let v = unsafe { core::ptr::read_volatile(p) };
            unsafe { core::ptr::write_volatile(p, v.wrapping_add(1)) };
        }};
    }
    macro_rules! check {
        ($field:ident, $want:expr) => {{
            let p = unsafe { core::ptr::addr_of!((*skb).$field) };
            if unsafe { core::ptr::read_volatile(p) } != $want {
                return 1;
            }
        }};
    }

    cb_step!(0);
    cb_step!(1);
    cb_step!(2);
    cb_step!(3);
    cb_step!(4);

    bump!(priority);
    bump!(tstamp);
    bump!(mark);

    check!(wire_len, 100);
    check!(gso_segs, 8);
    check!(gso_size, 10);
    check!(ingress_ifindex, 11);
    check!(ifindex, 1);
    check!(hwtstamp, 11);

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
