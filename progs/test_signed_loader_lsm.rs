#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_signed_loader_lsm.c
// bpf-rs-core idiom.
//
// The C source dereferences `prog->aux->sig.{keyring_serial,keyring_type,
// verdict}` directly (no BPF_CORE_READ): `prog` is a trusted BTF-typed
// pointer arg of the lsm/bpf_prog_load hook, and the verifier walks the
// nested struct/pointer chain itself. The `#[btf]` accessor chain below is
// the same CO-RE-relocated direct-dereference idiom used elsewhere (see
// tcp_ca_incompl_cong_ops.rs, bpf_iter_netlink.rs) for a trusted pointer hop
// (`.aux()`) followed by nested-struct field hops (`.sig().keyring_serial()`).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[btf]
struct bpf_prog_aux_sig {
    keyring_serial: i32,
    keyring_type: u8,
    verdict: u8,
}

#[btf]
struct bpf_prog_aux {
    sig: bpf_prog_aux_sig,
}

#[btf]
struct bpf_prog {
    aux: *mut bpf_prog_aux,
}

#[no_mangle]
static mut monitored_tid: u32 = 0;
#[no_mangle]
static mut sig_keyring_serial: i32 = 0;
#[no_mangle]
static mut sig_keyring_type: i32 = 0;
#[no_mangle]
static mut sig_verdict: i32 = 0;
#[no_mangle]
static mut seen: i32 = 0;

#[link_section = "lsm/bpf_prog_load"]
#[no_mangle]
extern "C" fn inspect_prog_load(ctx: *const u64) -> i32 {
    let tid = (bpf_get_current_pid_tgid() & 0xffffffff) as u32;

    let mtid = unsafe { monitored_tid };
    if mtid == 0 || tid != mtid {
        return 0;
    }

    unsafe { seen += 1 };

    let prog = arg(ctx, 0) as *const bpf_prog;
    let prog_ref = unsafe { &*prog };
    let aux = unsafe { *prog_ref.aux().as_ptr() };
    let aux_ref = unsafe { &*aux };

    let keyring_serial = unsafe { *aux_ref.sig().keyring_serial().as_ptr() };
    let keyring_type = unsafe { *aux_ref.sig().keyring_type().as_ptr() };
    let verdict = unsafe { *aux_ref.sig().verdict().as_ptr() };

    unsafe {
        sig_keyring_serial = keyring_serial;
        sig_keyring_type = keyring_type as i32;
        sig_verdict = verdict as i32;
    }

    0
}

bpf_object!("GPL");
