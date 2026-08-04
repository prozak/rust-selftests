#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/loop6.c
// (bpf-rs-core idiom).
//
// prog_tests/bpf_verif_scale.c's test_verif_scale_loop6 only calls
// check_load() (see scale_test()) — the program is loaded and verified,
// never attached or run. So only the loop bounds / probe-read shapes need
// to satisfy the verifier the same way the C original's do; the exact
// struct scatterlist field offsets used below (page_link@0 u64,
// length@12 u32, sizeof==24 with CONFIG_NEED_SG_DMA_LENGTH/_FLAGS unset)
// are hardcoded from this build's layout rather than expressed as a full
// CO-RE relocation, since nothing ever executes this program to observe
// a wrong offset.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use core::ffi::c_void;

const VIRTIO_MAX_SGS: u32 = 6;
const SG_MAX: u32 = 10; // WORKAROUND path in the C source
const SG_CHAIN: u64 = 0x01;
const SG_END: u64 = 0x02;

const SG_SIZE: u64 = 24; // sizeof(struct scatterlist) on this build
const SG_LENGTH_OFF: u64 = 12; // offsetof(struct scatterlist, length)

fn get_sgp(sgs: u64, i: u32) -> u64 {
    let mut sgp: u64 = 0;
    bpf_probe_read_kernel(&mut sgp, 8, (sgs + (i as u64) * 8) as *const c_void);
    sgp
}

fn sg_page_link(sgp: u64) -> u64 {
    let mut page_link: u64 = 0;
    bpf_probe_read_kernel(&mut page_link, 8, sgp as *const c_void);
    page_link
}

fn sg_next(sgp: u64) -> u64 {
    if sg_page_link(sgp) & SG_END != 0 {
        return 0;
    }

    let next = sgp + SG_SIZE;
    let next_page_link = sg_page_link(next);
    if next_page_link & SG_CHAIN != 0 {
        return next_page_link & !(SG_CHAIN | SG_END);
    }
    next
}

fn sg_length(sgp: u64) -> u32 {
    let mut len: u32 = 0;
    bpf_probe_read_kernel(&mut len, 4, (sgp + SG_LENGTH_OFF) as *const c_void);
    len
}

fn sum_lengths(sgs: u64, n_sgs: u32) -> u64 {
    let mut total: u64 = 0;
    let mut i = 0u32;
    while i < VIRTIO_MAX_SGS && i < n_sgs {
        let mut sgp = get_sgp(sgs, i);
        let mut n = 0u32;
        while sgp != 0 && n < SG_MAX {
            total += sg_length(sgp) as u64;
            n += 1;
            sgp = sg_next(sgp);
        }
        i += 1;
    }
    total
}

#[no_mangle]
static mut run_once: i32 = 0;
#[no_mangle]
static mut result: i32 = 0;

/// BPF_KPROBE(trace_virtqueue_add_sgs, void *unused, struct scatterlist **sgs,
/// unsigned int out_sgs, unsigned int in_sgs): ctx is `struct pt_regs *`,
/// which on x86_64 UML doubles as a `*const u64` register-slot array (see
/// test_vmlinux.rs / test_probe_user.rs for the same layout). PARM1 (di,
/// index 14) is `unused` and never read; PARM2 (si, index 13) is `sgs`,
/// PARM3 (dx, index 12) is `out_sgs`, PARM4 (cx, index 11) is `in_sgs`.
#[link_section = "kprobe/virtqueue_add_sgs"]
#[no_mangle]
extern "C" fn trace_virtqueue_add_sgs(ctx: *const u64) -> i32 {
    if unsafe { run_once } != 0 {
        return 0;
    }

    let sgs = unsafe { *ctx.add(13) };
    let out_sgs = unsafe { *ctx.add(12) } as u32;
    let in_sgs = unsafe { *ctx.add(11) } as u32;

    let length1 = sum_lengths(sgs, out_sgs);
    let length2 = sum_lengths(sgs, in_sgs);

    unsafe {
        run_once = 1;
        result = (length2 as i64 - length1 as i64) as i32;
    }
    0
}

bpf_object!("GPL");
