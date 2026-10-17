// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_kfunc_packet_access.c, translated
// by hand; include!d by the generated progs/verifier_kfunc_packet_access.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: kfunc_packet_write -- translate the C below (see the file comment)
//   SEC("tc")
//   __description("kfunc packet write requests writable skb")
//   __success
//   /* bpf_unclone_prologue() */
//   __xlated("r6 = *(u8 *)(r1 +{{[0-9]+}})")
//   __xlated("...")
//   __xlated("w6 &= {{(1|128)}}")
//   __xlated("...")
//   __xlated("if r6 == 0x0 goto")
//   __xlated("r6 = r1")
//   __xlated("r2 ^= r2")
//   __xlated("call")
//   __xlated("if r0 == 0x0 goto")
//   __xlated("w0 = 2")
//   __xlated("...")
//   __xlated("exit")
//   __xlated("r1 = r6")
//   int kfunc_packet_write(struct __sk_buff *skb)
//   {
//       void *data_end = (void *)(long)skb->data_end;
//       void *data = (void *)(long)skb->data;
//       struct bpf_sock_tuple tuple = {};
//       struct nf_conn *nfct;
//
//       if (data + sizeof(struct bpf_ct_opts) > data_end)
//           return 0;
//
//       /* An invalid tuple size makes bpf_skb_ct_lookup() write opts->error. */
//       nfct = bpf_skb_ct_lookup(skb, &tuple, 1, data, sizeof(struct bpf_ct_opts));
//       if (nfct)
//           bpf_ct_release(nfct);
//       return 0;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_packet_write(skb: *mut __sk_buff) -> i32 {
    let data_end = unsafe { (*skb).data_end } as usize;
    let data = unsafe { (*skb).data } as usize;
    let tuple = [0u8; 36]; // struct bpf_sock_tuple tuple = {}

    if data + 16 > data_end {
        // sizeof(struct bpf_ct_opts)
        return 0;
    }

    // an invalid tuple size makes bpf_skb_ct_lookup() write opts->error
    unsafe {
        let nfct = bpf_skb_ct_lookup(skb as *mut c_void, tuple.as_ptr() as *mut c_void, 1, data as *mut c_void, 16);
        if !nfct.is_null() {
            bpf_ct_release(nfct);
        }
    }
    0
}
