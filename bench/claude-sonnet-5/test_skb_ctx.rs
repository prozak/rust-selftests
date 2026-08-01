#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_skb_ctx.c
//
// TC program that validates the __sk_buff context the userspace test
// (prog_tests/skb_ctx.c) populates via BPF_PROG_TEST_RUN, mutates a few
// fields, and returns non-zero on any mismatch so the harness can assert
// the exact field values it expects back.

// UAPI struct __sk_buff, full layout (offsets verified against pahole
// dump of vmlinux BTF) — needed because narrow/wide ctx field accesses
// are rewritten by the verifier based on byte offset into this struct,
// so every field up to hwtstamp must sit at its real UAPI offset.
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
    let skb = unsafe { &mut *skb };

    for i in 0..5usize {
        if skb.cb[i] != (i as u32) + 1 {
            return 1;
        }
        skb.cb[i] += 1;
    }
    skb.priority += 1;
    skb.tstamp += 1;
    skb.mark += 1;

    if skb.wire_len != 100 {
        return 1;
    }
    if skb.gso_segs != 8 {
        return 1;
    }
    if skb.gso_size != 10 {
        return 1;
    }
    if skb.ingress_ifindex != 11 {
        return 1;
    }
    if skb.ifindex != 1 {
        return 1;
    }
    if skb.hwtstamp != 11 {
        return 1;
    }

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
