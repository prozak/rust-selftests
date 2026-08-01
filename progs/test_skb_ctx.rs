#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_skb_ctx.c,
// bpf-rs-core idiom.
//
// A TC (SCHED_CLS) program run via bpf_prog_test_run_opts with a caller
// supplied ctx: it verifies cb[]/wire_len/gso_*/ifindex/hwtstamp hold the
// values the userspace test seeded, and increments cb[i], priority, tstamp
// and mark so the test can observe them in ctx_out.
//
// cb[] is accessed with constant indices only (the C loop is fully
// unrolled) — the verifier rejects variable-offset ctx access. Volatile
// accesses keep each ctx load/store separate and 4/8-byte sized.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_object, vload, vstore};

#[link_section = "tc"]
#[no_mangle]
extern "C" fn process(skb: *mut __sk_buff) -> i32 {
    macro_rules! cb_step {
        ($i:expr) => {{
            let v = vload!((*skb).cb[$i]);
            if v != $i as u32 + 1 {
                return 1;
            }
            vstore!((*skb).cb[$i], v.wrapping_add(1));
        }};
    }
    macro_rules! bump {
        ($field:ident) => {{
            let v = vload!((*skb).$field);
            vstore!((*skb).$field, v.wrapping_add(1));
        }};
    }
    macro_rules! check {
        ($field:ident, $want:expr) => {{
            if vload!((*skb).$field) != $want {
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

bpf_object!("GPL");
