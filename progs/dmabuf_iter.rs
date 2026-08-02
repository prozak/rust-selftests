#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/dmabuf_iter.c
// (bpf-rs-core idiom).
//
// dmabuf_collector mirrors the C original's use of bpf_core_read /
// BPF_CORE_READ_INTO for every field of the iter-provided `dmabuf` (rather
// than direct dereference): the C source does the same even for
// single-hop reads off `dmabuf` itself, so every hop here goes through
// bpf_probe_read_kernel for parity, `dmabuf->file->f_inode->i_ino` chased
// one pointer hop at a time (each hop re-roots a `#[btf]` accessor at the
// freshly-read pointer value, same pattern as bpf_iter_netlink.rs's
// `sk_socket`/`socket_alloc` chase).
//
// iter_dmabuf_for_each translates the C source's `bpf_for_each(dmabuf, d)`
// open-coded iterator as literally as possible: extern kfuncs
// bpf_iter_dmabuf_new/next/destroy, called directly in place of the macro.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
    bpf_seq_printf,
};
use btf_macros::btf;
use core::ffi::c_void;

const DMA_BUF_NAME_LEN: usize = 32;
const BPF_EXIST: u64 = 2;

bpf_map! {
    testbuf_hash {
        r#type: *const [i32; bpf_rs_core::maps::HASH],
        key_size: *const [i32; DMA_BUF_NAME_LEN],
        value: *const bool,
        max_entries: *const [i32; 5],
    }
}

#[btf]
struct inode {
    i_ino: u64,
}

#[btf]
struct file {
    f_inode: *mut inode,
}

#[btf]
struct dma_buf {
    size: u64,
    file: *mut file,
    name: *const u8,
    exp_name: *const u8,
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__dmabuf {
    meta: *mut bpf_iter_meta,
    dmabuf: *mut dma_buf,
}

fn sanitize_string(buf: &mut [u8; DMA_BUF_NAME_LEN]) {
    for c in buf.iter_mut() {
        if *c == 0 {
            break;
        }
        if *c == b'\n' {
            *c = b' ';
        }
    }
}

#[link_section = "iter/dmabuf"]
#[no_mangle]
extern "C" fn dmabuf_collector(ctx: *const bpf_iter__dmabuf) -> i32 {
    let ctx = unsafe { &*ctx };
    let dmabuf = ctx.dmabuf;
    if dmabuf.is_null() {
        return 0;
    }
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let dmabuf_ref = unsafe { &*dmabuf };

    let mut file_ptr: *mut file = core::ptr::null_mut();
    if bpf_probe_read_kernel(
        &mut file_ptr,
        core::mem::size_of::<*mut file>() as u32,
        dmabuf_ref.file().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    let mut inode_ptr: *mut inode = core::ptr::null_mut();
    if bpf_probe_read_kernel(
        &mut inode_ptr,
        core::mem::size_of::<*mut inode>() as u32,
        unsafe { &*file_ptr }.f_inode().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    let mut inode_num: u64 = 0;
    if bpf_probe_read_kernel(
        &mut inode_num,
        core::mem::size_of::<u64>() as u32,
        unsafe { &*inode_ptr }.i_ino().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    let mut size: u64 = 0;
    if bpf_probe_read_kernel(
        &mut size,
        core::mem::size_of::<u64>() as u32,
        dmabuf_ref.size().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    let mut pname: *const u8 = core::ptr::null();
    if bpf_probe_read_kernel(
        &mut pname,
        core::mem::size_of::<*const u8>() as u32,
        dmabuf_ref.name().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    let mut exporter: *const u8 = core::ptr::null();
    if bpf_probe_read_kernel(
        &mut exporter,
        core::mem::size_of::<*const u8>() as u32,
        dmabuf_ref.exp_name().as_ptr() as *const c_void,
    ) != 0
    {
        return 1;
    }

    // Buffers are not required to be named.
    let mut name: [u8; DMA_BUF_NAME_LEN] = [0; DMA_BUF_NAME_LEN];
    if !pname.is_null() {
        if bpf_probe_read_kernel_str(
            name.as_mut_ptr() as *mut c_void,
            DMA_BUF_NAME_LEN as u32,
            pname as *const c_void,
        ) < 0
        {
            return 1;
        }
        // Name strings can be provided by userspace.
        sanitize_string(&mut name);
    }

    static FMT: [u8; 16] = *b"%lu\n%llu\n%s\n%s\n\0";
    let params: [u64; 4] = [inode_num, size, name.as_ptr() as u64, exporter as u64];
    bpf_seq_printf(
        seq,
        FMT.as_ptr() as *const c_void,
        FMT.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

#[repr(C)]
struct bpf_iter_dmabuf {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_dmabuf_new(it: *mut bpf_iter_dmabuf) -> i32;
    fn bpf_iter_dmabuf_next(it: *mut bpf_iter_dmabuf) -> *mut dma_buf;
    fn bpf_iter_dmabuf_destroy(it: *mut bpf_iter_dmabuf);
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn iter_dmabuf_for_each(_ctx: *const c_void) -> i32 {
    let mut it = bpf_iter_dmabuf { __opaque: [0; 1] };
    unsafe { bpf_iter_dmabuf_new(&mut it) };

    loop {
        let d = unsafe { bpf_iter_dmabuf_next(&mut it) };
        if d.is_null() {
            break;
        }
        let d_ref = unsafe { &*d };

        let mut pname: *const u8 = core::ptr::null();
        if bpf_probe_read_kernel(
            &mut pname,
            core::mem::size_of::<*const u8>() as u32,
            d_ref.name().as_ptr() as *const c_void,
        ) != 0
        {
            unsafe { bpf_iter_dmabuf_destroy(&mut it) };
            return 1;
        }

        // Buffers are not required to be named.
        if pname.is_null() {
            continue;
        }

        let mut name: [u8; DMA_BUF_NAME_LEN] = [0; DMA_BUF_NAME_LEN];
        let len = bpf_probe_read_kernel_str(
            name.as_mut_ptr() as *mut c_void,
            DMA_BUF_NAME_LEN as u32,
            pname as *const c_void,
        );
        if len < 0 {
            unsafe { bpf_iter_dmabuf_destroy(&mut it) };
            return 1;
        }

        // The entire name buffer is used as a map key.
        // Zeroize any uninitialized trailing bytes after the NUL. Volatile
        // stores keep LLVM from recognizing this as a memset() libcall,
        // which the BPF backend cannot lower.
        let name_ptr = name.as_mut_ptr();
        let mut i = len as usize;
        while i < DMA_BUF_NAME_LEN {
            unsafe { core::ptr::write_volatile(name_ptr.add(i), 0) };
            i += 1;
        }

        let found = bpf_map_lookup_elem(&testbuf_hash, &name);
        if !found.is_null() {
            let t: bool = true;
            bpf_map_update_elem(&testbuf_hash, &name, &t, BPF_EXIST);
        }
    }

    unsafe { bpf_iter_dmabuf_destroy(&mut it) };
    0
}

bpf_object!("GPL");
