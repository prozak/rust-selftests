// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_netfilter_ctx.c, translated
// by hand; include!d by the generated progs/verifier_netfilter_ctx.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_dynptr_write;
use btf_macros::btf;

const NF_DROP: i32 = 0;
const NF_ACCEPT: i32 = 1;

/// struct bpf_nf_ctx (net/netfilter/nf_bpf_link.h): the hook state and the
/// kernel's sk_buff, both read with CO-RE through the views below.
#[repr(C)]
struct bpf_nf_ctx {
    state: *mut nf_hook_state,
    skb: *mut sk_buff,
}

#[btf]
struct sock {}

#[btf]
struct nf_hook_state {
    pf: u8,
    sk: *mut sock,
}

#[btf]
struct sk_buff {
    len: u32,
    data: *mut u8,
}

/// `struct bpf_dynptr { __u64 __opaque[2]; }`.
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

/// struct iphdr (linux/ip.h), packed; version/ihl share the first byte.
#[repr(C, packed)]
struct iphdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

/// struct tcphdr (linux/tcp.h), packed; only dest is read.
#[repr(C, packed)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    res1_doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// HAND: with_invalid_ctx_access_test5 -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter valid context read and invalid write")
//   __failure __msg("only read is supported")
//   int with_invalid_ctx_access_test5(struct bpf_nf_ctx *ctx)
//   {
//       struct nf_hook_state *state = (void *)ctx->state;
//
//       state->sk = NULL;
//       return NF_ACCEPT;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn with_invalid_ctx_access_test5(ctx: *mut bpf_nf_ctx) -> i32 {
    // state->sk = NULL: a write through the read-only ctx->state
    let state = unsafe { &*(*ctx).state };
    unsafe { core::ptr::write(state.sk().as_mut_ptr(), core::ptr::null_mut()) };
    NF_ACCEPT
}

// HAND: with_valid_ctx_access_test6 -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with skb and state read access")
//   __success __failure_unpriv
//   __retval(0)
//   int with_valid_ctx_access_test6(struct bpf_nf_ctx *ctx)
//   {
//       struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
//       const struct nf_hook_state *state = ctx->state;
//       const struct iphdr *iph;
//       const struct tcphdr *th;
//       u8 buffer_iph[20] = {};
//       u8 buffer_th[40] = {};
//       struct bpf_dynptr ptr;
//       uint8_t ihl;
//
//       if (ctx->skb->len <= 20 || bpf_dynptr_from_skb(skb, 0, &ptr))
//           return NF_ACCEPT;
//
//       iph = bpf_dynptr_slice(&ptr, 0, buffer_iph, sizeof(buffer_iph));
//       if (!iph)
//           return NF_ACCEPT;
//
//       if (state->pf != 2)
//           return NF_ACCEPT;
//
//       ihl = iph->ihl << 2;
//
//       th = bpf_dynptr_slice(&ptr, ihl, buffer_th, sizeof(buffer_th));
//       if (!th)
//           return NF_ACCEPT;
//
//       return th->dest == bpf_htons(22) ? NF_ACCEPT : NF_DROP;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn with_valid_ctx_access_test6(ctx: *mut bpf_nf_ctx) -> i32 {
    let skb = unsafe { (*ctx).skb } as *mut __sk_buff;
    let state = unsafe { &*(*ctx).state };
    let mut buffer_iph = [0u8; 20];
    let mut buffer_th = [0u8; 40];
    let mut ptr = core::mem::MaybeUninit::<bpf_dynptr>::uninit(); // uninitialized, as in C

    let len = unsafe { *(&*(*ctx).skb).len().as_ptr() };
    if len <= 20 || unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, ptr.as_mut_ptr() as *mut c_void) } != 0 {
        return NF_ACCEPT;
    }

    let iph = unsafe { bpf_dynptr_slice(ptr.as_mut_ptr() as *mut c_void, 0, buffer_iph.as_mut_ptr() as *mut c_void, 20) } as *const iphdr;
    if iph.is_null() {
        return NF_ACCEPT;
    }

    if unsafe { *state.pf().as_ptr() } != 2 {
        return NF_ACCEPT;
    }

    // iph->ihl << 2: ihl is the low nibble of the first byte
    let ihl = ((unsafe { (*iph).version_ihl } & 0xf) << 2) as u64;

    let th = unsafe { bpf_dynptr_slice(ptr.as_mut_ptr() as *mut c_void, ihl, buffer_th.as_mut_ptr() as *mut c_void, 40) } as *const tcphdr;
    if th.is_null() {
        return NF_ACCEPT;
    }

    if unsafe { (*th).dest } == 22u16.to_be() { NF_ACCEPT } else { NF_DROP }
}

// HAND: skb_len_write -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with skb write access")
//   __failure __msg("only read is supported")
//   int skb_len_write(struct bpf_nf_ctx *ctx)
//   {
//       ctx->skb->len = 1;
//       return 1;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn skb_len_write(ctx: *mut bpf_nf_ctx) -> i32 {
    // ctx->skb->len = 1: a write through the read-only skb
    let skb = unsafe { &*(*ctx).skb };
    unsafe { core::ptr::write(skb.len().as_mut_ptr(), 1) };
    1
}

// HAND: skb_data_write -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with skb data write access")
//   __failure __msg("cannot write into rdonly_untrusted_mem")
//   int skb_data_write(struct bpf_nf_ctx *ctx)
//   {
//       ctx->skb->data[0] = 0;
//       return 1;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn skb_data_write(ctx: *mut bpf_nf_ctx) -> i32 {
    // ctx->skb->data[0] = 0: a write into rdonly_untrusted_mem
    let skb = unsafe { &*(*ctx).skb };
    let data = unsafe { *skb.data().as_ptr() };
    unsafe { core::ptr::write(data, 0) };
    1
}

// HAND: with_dynptr_write -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with bpf_dynptr_write")
//   __success __failure_unpriv
//   __retval(0)
//   int with_dynptr_write(struct bpf_nf_ctx *ctx)
//   {
//       struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
//       struct bpf_dynptr ptr;
//       u8 buffer[1] = {};
//
//       if (bpf_dynptr_from_skb(skb, 0, &ptr))
//           return 1;
//
//       if (bpf_dynptr_write(ptr.as_ptr(), 0, buffer, sizeof(buffer), 0))
//           return 0; /* must always fail */
//
//       return 1;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn with_dynptr_write(ctx: *mut bpf_nf_ctx) -> i32 {
    let skb = unsafe { (*ctx).skb } as *mut __sk_buff;
    // the C's frame: ptr at fp-16, buffer below it (rustc places the last
    // local highest, so the order is reversed here)
    let mut buffer = [0u8; 1];
    let mut ptr = core::mem::MaybeUninit::<bpf_dynptr>::uninit(); // uninitialized, as in C

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, ptr.as_mut_ptr() as *mut c_void) } != 0 {
        return 1;
    }

    if bpf_dynptr_write(ptr.as_ptr(), 0, buffer.as_mut_ptr() as *mut c_void, 1, 0) != 0 {
        return 0; // must always fail
    }

    1
}

// HAND: with_dynptr_rdwr -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with bpf_dynptr_slice_rdwr")
//   __failure __msg("the prog does not allow writes to packet data")
//   int with_dynptr_rdwr(struct bpf_nf_ctx *ctx)
//   {
//       struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
//       u8 buffer_iph[20] = {};
//       struct bpf_dynptr ptr;
//       struct iphdr *iph;
//
//       if (bpf_dynptr_from_skb(skb, 0, &ptr))
//           return 1;
//
//       iph = bpf_dynptr_slice_rdwr(&ptr, 0, buffer_iph, sizeof(buffer_iph));
//       if (!iph)
//           return 0;
//
//       return 1;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn with_dynptr_rdwr(ctx: *mut bpf_nf_ctx) -> i32 {
    let skb = unsafe { (*ctx).skb } as *mut __sk_buff;
    let mut buffer_iph = [0u8; 20];
    let mut ptr = core::mem::MaybeUninit::<bpf_dynptr>::uninit(); // uninitialized, as in C

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, ptr.as_mut_ptr() as *mut c_void) } != 0 {
        return 1;
    }

    let iph = unsafe { bpf_dynptr_slice_rdwr(ptr.as_mut_ptr() as *mut c_void, 0, buffer_iph.as_mut_ptr() as *mut c_void, 20) } as *mut iphdr;
    if iph.is_null() {
        return 0;
    }

    1
}

// HAND: with_dynptr_store -- translate the C below (see the file comment)
//   SEC("netfilter")
//   __description("netfilter test prog with bpf_dynptr_slice + write")
//   __failure __msg("cannot write into rdonly_mem")
//   int with_dynptr_store(struct bpf_nf_ctx *ctx)
//   {
//       struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
//       u8 buffer_iph[20] = {};
//       struct bpf_dynptr ptr;
//       struct iphdr *iph;
//
//       if (bpf_dynptr_from_skb(skb, 0, &ptr))
//           return 1;
//
//       iph = bpf_dynptr_slice(&ptr, 0, buffer_iph, sizeof(buffer_iph));
//       if (!iph)
//           return 0;
//       iph->protocol = 42;
//
//       return 1;
//   }
#[link_section = "netfilter"]
#[no_mangle]
extern "C" fn with_dynptr_store(ctx: *mut bpf_nf_ctx) -> i32 {
    let skb = unsafe { (*ctx).skb } as *mut __sk_buff;
    let mut buffer_iph = [0u8; 20];
    let mut ptr = core::mem::MaybeUninit::<bpf_dynptr>::uninit(); // uninitialized, as in C

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, ptr.as_mut_ptr() as *mut c_void) } != 0 {
        return 1;
    }

    let iph = unsafe { bpf_dynptr_slice(ptr.as_mut_ptr() as *mut c_void, 0, buffer_iph.as_mut_ptr() as *mut c_void, 20) } as *mut iphdr;
    if iph.is_null() {
        return 0;
    }
    // iph->protocol = 42: a write into the read-only slice
    unsafe { core::ptr::write(core::ptr::addr_of_mut!((*iph).protocol), 42) };

    1
}
