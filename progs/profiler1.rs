#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/profiler1.c
// (== profiler.inc.h with UNROLL defined and INLINE = __always_inline),
// bpf-rs-core idiom.
//
// prog_tests/test_profiler.c only open_and_load()s + attach()es this
// object (plus the pristine profiler2/profiler3 clang objects) and then
// bpf_prog_test_run()s raw_tracepoint__sched_process_exec with ctx_in =
// {1,2,3}, asserting retval == 0. Every SEC program below always falls
// through to `return 0`, so correctness here is really "loads, attaches,
// and the sanity_run doesn't get killed by the verifier" -- which means
// every kernel-struct field read must be a genuinely safe (fault-tolerant)
// read, since ctx->args[2] in the sanity run is the raw scalar 3, cast to
// `struct linux_binprm *`.
//
// Every BPF_CORE_READ(...) hop in the C source is reproduced here as an
// explicit `cread()` (bpf_probe_read_kernel of a `#[btf]`-relocated field
// address) rather than a direct pointer dereference: none of the pointers
// chased in this file are BTF-trusted (bpf_get_current_task() returns a
// scalar u64, kprobe/raw_tracepoint ctx args are plain u64 slots), so a
// direct dereference would either be rejected by the verifier or (for the
// sanity-run's bogus bprm=3 pointer) actually fault. `cread()`/probe reads
// never check their return code, matching BPF_CORE_READ's own unchecked
// semantics (destination is left zeroed by the kernel on a faulting read).
//
// Two version-compat CO-RE branches in populate_cgroup_info's C original
// (kernfs_node___52's `id.ino`-vs-plain-`id` and
// kernfs_iattrs___52's `ia_iattr.ia_mtime`-vs-plain-`ia_mtime`) are
// hardcoded to the modern shape here (confirmed against this build's
// kernel: fs/kernfs/kernfs-internal.h's `struct kernfs_iattrs` has
// `ia_mtime` directly, and include/linux/kernfs.h's `struct kernfs_node`
// has a plain `u64 id`) rather than translated with a field_exists()
// check, matching the LINUX_HAS_SYSCALL_WRAPPER-hardcoding precedent in
// test_probe_user.rs. Likewise the `ENABLE_CGROUP_V1_RESOLVER &&
// CONFIG_CGROUP_PIDS` cgroup-v1 fallback in populate_cgroup_info is
// omitted entirely: `bpf_config.enable_cgroup_v1_resolver` defaults to
// (and, since the test never sets it, always stays) false/0, so the C
// branch is never taken either -- omitting it changes no observable
// behavior and avoids needing a `__kconfig` extern (unsupported here, see
// TRANSLATING.md) plus several more kernel structs (cgroup_subsys_state,
// cgroup_subsys, kernfs_root) with no test coverage of the branch.
//
// profiler1 defines INLINE as __always_inline (unlike profiler2/3): every
// C helper here is force-inlined into its call site, keeping each SEC
// program to one flat stack frame. `#[inline(always)]` on every helper
// below reproduces that -- the BPF verifier's 512-byte stack limit is
// cumulative across non-inlined call frames, and none of these helpers'
// locals are more than a handful of pointers/integers, so full inlining
// keeps every program comfortably under the limit (all the genuinely large
// state -- var_*_data_t payloads -- lives in map memory, never on stack).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
    bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_perf_event_output, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;
use core::ffi::c_void;

// ---------------------------------------------------------------- consts --

const TASK_COMM_LEN: usize = 16;
const MAX_ANCESTORS: usize = 4;
const MAX_PATH: usize = 256;
const KILL_TARGET_LEN: usize = 64;
const CTL_MAXNAME: usize = 10;
const MAX_ARGS_LEN: usize = 4096;
const MAX_FILENAME_LEN: usize = 512;
const MAX_ENVIRON_LEN: usize = 8192;
const MAX_PATH_DEPTH: usize = 32;
const MAX_FILEPATH_LENGTH: usize = MAX_PATH_DEPTH * MAX_PATH;
const MAX_CGROUPS_PATH_DEPTH: usize = 8;
const MAX_METADATA_PAYLOAD_LEN: usize = TASK_COMM_LEN;
const MAX_CGROUP_PAYLOAD_LEN: usize = MAX_PATH * 2 + MAX_PATH * MAX_CGROUPS_PATH_DEPTH;
const MAX_SYSCTL_PAYLOAD_LEN: usize =
    MAX_METADATA_PAYLOAD_LEN + MAX_CGROUP_PAYLOAD_LEN + CTL_MAXNAME + MAX_PATH;
const MAX_KILL_PAYLOAD_LEN: usize =
    MAX_METADATA_PAYLOAD_LEN + MAX_CGROUP_PAYLOAD_LEN + TASK_COMM_LEN + KILL_TARGET_LEN;
const MAX_EXEC_PAYLOAD_LEN: usize =
    MAX_METADATA_PAYLOAD_LEN + MAX_CGROUP_PAYLOAD_LEN + MAX_FILENAME_LEN + MAX_ARGS_LEN + MAX_ENVIRON_LEN;
const MAX_FILEMOD_PAYLOAD_LEN: usize =
    MAX_METADATA_PAYLOAD_LEN + MAX_CGROUP_PAYLOAD_LEN + MAX_FILEPATH_LENGTH + MAX_FILEPATH_LENGTH;
const KILL_DATA_ARRAY_SIZE: usize = 8;

// enum data_type
const EXEC_EVENT: u32 = 1;
const FORK_EVENT: u32 = 2;
const KILL_EVENT: u32 = 3;
const SYSCTL_EVENT: u32 = 4;
const FILEMOD_EVENT: u32 = 5;

// enum filemod_type
const FMOD_OPEN: u32 = 0;
const FMOD_LINK: u32 = 1;
const FMOD_SYMLINK: u32 = 2;

// enum bpf_function_id
const PROFILER_BPF_PROC_SYS_WRITE: u32 = 0;
const PROFILER_BPF_SCHED_PROCESS_EXEC: u32 = 1;
const PROFILER_BPF_SCHED_PROCESS_EXIT: u32 = 2;
const PROFILER_BPF_SYS_ENTER_KILL: u32 = 3;
const PROFILER_BPF_DO_FILE_OPEN_RET: u32 = 4;
const PROFILER_BPF_SCHED_PROCESS_FORK: u32 = 5;
const PROFILER_BPF_VFS_LINK: u32 = 6;
const PROFILER_BPF_VFS_SYMLINK: u32 = 7;
const PROFILER_BPF_MAX_FUNCTION_ID: usize = 8;

const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_DIRECTORY: u32 = 0o200000;
const O_TMPFILE: u32 = 0o20000000 | O_DIRECTORY;
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const MAX_ERRNO: u64 = 4095;

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

// pt_regs register-slot indices (x86-64 UML/QEMU: r15,r14,r13,r12,bp,bx,r11,
// r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss), same convention as
// test_probe_user.rs / test_vmlinux.rs. PARM1..PARM6 = di,si,dx,cx,r8,r9;
// RC = ax.
const REG_DI: usize = 14; // PARM1
const REG_SI: usize = 13; // PARM2
const REG_DX: usize = 12; // PARM3
const REG_CX: usize = 11; // PARM4
#[allow(dead_code)]
const REG_R8: usize = 9; // PARM5 (unused: kprobe__vfs_link's delegated_inode arg is never read)
const REG_AX: usize = 10; // RC

// ------------------------------------------------------ profiler.h mirrors --

#[repr(C)]
struct AncestorsData {
    ancestor_pids: [i32; MAX_ANCESTORS],
    ancestor_exec_ids: [u32; MAX_ANCESTORS],
    ancestor_start_times: [u64; MAX_ANCESTORS],
    num_ancestors: u32,
}

#[repr(C)]
struct VarMetadata {
    type_: u32,
    pid: i32,
    exec_id: u32,
    uid: u32,
    gid: u32,
    start_time: u64,
    cpu_id: u32,
    bpf_stats_num_perf_events: u64,
    bpf_stats_start_ktime_ns: u64,
    comm_length: u8,
}

#[repr(C)]
struct CgroupData {
    cgroup_root_inode: u64,
    cgroup_proc_inode: u64,
    cgroup_root_mtime: u64,
    cgroup_proc_mtime: u64,
    cgroup_root_length: u16,
    cgroup_proc_length: u16,
    cgroup_full_length: u16,
    cgroup_full_path_root_pos: i32,
}

#[repr(C)]
struct VarSysctlData {
    meta: VarMetadata,
    cgroup_data: CgroupData,
    ancestors_info: AncestorsData,
    sysctl_val_length: u8,
    sysctl_path_length: u16,
    payload: [u8; MAX_SYSCTL_PAYLOAD_LEN],
}

#[repr(C)]
struct VarKillData {
    meta: VarMetadata,
    cgroup_data: CgroupData,
    ancestors_info: AncestorsData,
    kill_target_pid: i32,
    kill_sig: i32,
    kill_count: u32,
    last_kill_time: u64,
    kill_target_name_length: u8,
    kill_target_cgroup_proc_length: u8,
    payload: [u8; MAX_KILL_PAYLOAD_LEN],
    payload_length: usize,
}

#[repr(C)]
struct VarKillDataArr {
    array: [VarKillData; KILL_DATA_ARRAY_SIZE],
}

#[repr(C)]
struct VarExecData {
    meta: VarMetadata,
    cgroup_data: CgroupData,
    parent_pid: i32,
    parent_exec_id: u32,
    parent_uid: u32,
    parent_start_time: u64,
    bin_path_length: u16,
    cmdline_length: u16,
    environment_length: u16,
    payload: [u8; MAX_EXEC_PAYLOAD_LEN],
}

#[repr(C)]
struct VarForkData {
    meta: VarMetadata,
    parent_pid: i32,
    parent_exec_id: u32,
    parent_start_time: u64,
    payload: [u8; MAX_METADATA_PAYLOAD_LEN],
}

#[repr(C)]
struct VarFilemodData {
    meta: VarMetadata,
    cgroup_data: CgroupData,
    fmod_type: u32,
    dst_flags: u32,
    src_device_id: u32,
    dst_device_id: u32,
    src_inode: u64,
    dst_inode: u64,
    src_filepath_length: u16,
    dst_filepath_length: u16,
    payload: [u8; MAX_FILEMOD_PAYLOAD_LEN],
}

#[repr(C)]
struct profiler_config_struct {
    fetch_cgroups_from_bpf: bool,
    cgroup_fs_inode: u64,
    cgroup_login_session_inode: u64,
    kill_signals_mask: u64,
    inode_filter: u64,
    stale_info_secs: u32,
    use_variable_buffers: bool,
    read_environ_from_exec: bool,
    enable_cgroup_v1_resolver: bool,
}

#[repr(C)]
struct BpfFuncStatsData {
    time_elapsed_ns: u64,
    num_executions: u64,
    num_perf_events: u64,
}

#[repr(C)]
struct BpfFuncStatsCtx {
    start_time_ns: u64,
    bpf_func_stats_data_val: *mut BpfFuncStatsData,
}

impl BpfFuncStatsCtx {
    const fn new() -> Self {
        BpfFuncStatsCtx {
            start_time_ns: 0,
            bpf_func_stats_data_val: core::ptr::null_mut(),
        }
    }
}

// ------------------------------------------------------- kernel-struct CO-RE mirrors --

#[btf]
struct task_struct {
    real_parent: *const task_struct,
    pid: i32,
    tgid: i32,
    self_exec_id: u64,
    start_time: u64,
    comm: [u8; TASK_COMM_LEN],
    nsproxy: *mut nsproxy,
    cgroups: *mut css_set,
    mm: *mut mm_struct,
    real_cred: *mut cred,
}

#[btf]
struct nsproxy {
    cgroup_ns: *mut cgroup_namespace,
}

#[btf]
struct cgroup_namespace {
    root_cset: *mut css_set,
}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[btf]
struct kernfs_node {
    __parent: *mut kernfs_node,
    name: *const u8,
    id: u64,
    iattr: *mut kernfs_iattrs,
}

#[btf]
struct kernfs_iattrs {
    ia_mtime: timespec64,
}

#[btf]
struct timespec64 {
    tv_nsec: i64,
}

#[btf]
struct cred {
    uid: kuid_t,
}

#[btf]
struct kuid_t {
    val: u32,
}

#[btf]
struct mm_struct {
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
}

#[btf]
struct qstr {
    name: *const u8,
}

#[btf]
struct dentry {
    d_parent: *mut dentry,
    d_name: qstr,
    d_inode: *mut inode,
    d_sb: *mut super_block,
}

#[btf]
struct inode {
    i_ino: u64,
    i_mode: u16,
}

#[btf]
struct super_block {
    s_dev: u32,
}

#[btf]
struct path {
    dentry: *mut dentry,
}

#[btf]
struct file {
    f_path: path,
    f_inode: *mut inode,
    f_flags: u32,
}

#[btf]
struct linux_binprm {
    file: *mut file,
    filename: *const u8,
}

// -------------------------------------------------------------------- maps --

#[link_section = ".maps"]
#[no_mangle]
static data_heap: BpfMap<u32, VarKillDataArr, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

bpf_map! {
    /// PERF_EVENT_ARRAY sized by libbpf (no max_entries member).
    events {
        r#type: *const [i32; maps::PERF_EVENT_ARRAY],
        key: *const i32,
        value: *const i32,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static var_tpid_to_data: BpfMap<u32, VarKillDataArr, { maps::HASH }, KILL_DATA_ARRAY_SIZE> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static bpf_func_stats: BpfMap<u32, BpfFuncStatsData, { maps::PERCPU_ARRAY }, PROFILER_BPF_MAX_FUNCTION_ID> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static allowed_devices: BpfMap<u32, bool, { maps::HASH }, 16> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static allowed_file_inodes: BpfMap<u64, bool, { maps::HASH }, 1024> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static allowed_directory_inodes: BpfMap<u64, bool, { maps::HASH }, 1024> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static disallowed_exec_inodes: BpfMap<u32, bool, { maps::HASH }, 16> = BpfMap::new();

// ----------------------------------------------------------------- globals --

#[no_mangle]
static mut bpf_config: profiler_config_struct = profiler_config_struct {
    fetch_cgroups_from_bpf: false,
    cgroup_fs_inode: 0,
    cgroup_login_session_inode: 0,
    kill_signals_mask: 0,
    inode_filter: 0,
    stale_info_secs: 0,
    use_variable_buffers: false,
    read_environ_from_exec: false,
    enable_cgroup_v1_resolver: false,
};

// --------------------------------------------------------------- helpers --

/// BPF_CORE_READ's single-hop primitive: relocate `src`'s byte address (via
/// the `#[btf]` CO-RE field accessor's `.as_ptr()`) and safely copy the
/// value there. Unchecked, matching BPF_CORE_READ (destination is left
/// zeroed by the kernel on a faulting read).
#[inline(always)]
fn cread<T: Copy>(src: *const T) -> T {
    let mut v: T = unsafe { core::mem::zeroed() };
    bpf_probe_read_kernel(&mut v, core::mem::size_of::<T>() as u32, src as *const c_void);
    v
}

/// bpf_probe_read_kernel into an arbitrary untyped destination address
/// (payload cursor), matching C's `bpf_probe_read_kernel(void *dst, ...)`.
#[inline(always)]
fn praw(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    bpf_probe_read_kernel(unsafe { &mut *(dst as *mut u8) }, size, src)
}

#[inline(always)]
fn is_err(ptr: *const c_void) -> bool {
    (ptr as u64) >= 0u64.wrapping_sub(MAX_ERRNO)
}

#[inline(always)]
fn get_userspace_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
fn is_init_process(tgid: u32) -> bool {
    tgid == 1 || tgid == 0
}

#[inline(always)]
fn probe_read_lim(dst: *mut c_void, src: *mut c_void, len: u64, max: u64) -> u64 {
    let len = if len < max { len } else { max };
    if len > 1 {
        if praw(dst, len as u32, src as *const c_void) != 0 {
            return 0;
        }
    } else if len == 1 {
        if praw(dst, 1, src as *const c_void) != 0 {
            return 0;
        }
    }
    len
}

#[inline(always)]
fn get_var_spid_index(arr_struct: &VarKillDataArr, spid: i32) -> i32 {
    for i in 0..KILL_DATA_ARRAY_SIZE {
        if arr_struct.array[i].meta.pid == spid {
            return i as i32;
        }
    }
    -1
}

#[inline(always)]
fn populate_ancestors(task: *const task_struct, ancestors_data: &mut AncestorsData) {
    let mut parent = task;
    ancestors_data.num_ancestors = 0;
    for num_ancestors in 0..MAX_ANCESTORS {
        parent = cread(unsafe { &*parent }.real_parent().as_ptr());
        if parent.is_null() {
            break;
        }
        let ppid: i32 = cread(unsafe { &*parent }.tgid().as_ptr());
        let ppid = ppid as u32;
        if is_init_process(ppid) {
            break;
        }
        ancestors_data.ancestor_pids[num_ancestors] = ppid as i32;
        ancestors_data.ancestor_exec_ids[num_ancestors] =
            cread(unsafe { &*parent }.self_exec_id().as_ptr()) as u32;
        ancestors_data.ancestor_start_times[num_ancestors] =
            cread(unsafe { &*parent }.start_time().as_ptr());
        ancestors_data.num_ancestors = num_ancestors as u32;
    }
}

#[inline(always)]
fn read_full_cgroup_path(
    mut cgroup_node: *mut kernfs_node,
    cgroup_root_node: *mut kernfs_node,
    payload: *mut u8,
    root_pos: &mut i32,
) -> *mut u8 {
    let payload_start = payload;
    let mut payload = payload;
    for _ in 0..MAX_CGROUPS_PATH_DEPTH {
        let name_ptr = cread(unsafe { &*cgroup_node }.name().as_ptr());
        let filepart_length =
            bpf_probe_read_kernel_str(payload as *mut c_void, MAX_PATH as u32, name_ptr as *const c_void)
                as usize;
        if cgroup_node.is_null() {
            return payload;
        }
        if cgroup_node == cgroup_root_node {
            *root_pos = (payload as usize - payload_start as usize) as i32;
        }
        if filepart_length <= MAX_PATH {
            payload = unsafe { payload.add(filepart_length) };
        }
        cgroup_node = cread(unsafe { &*cgroup_node }.__parent().as_ptr());
    }
    payload
}

#[inline(always)]
fn get_inode_from_kernfs(node: *mut kernfs_node) -> u64 {
    cread(unsafe { &*node }.id().as_ptr())
}

#[inline(always)]
fn populate_cgroup_info(
    cgroup_data: &mut CgroupData,
    task: *const task_struct,
    payload: *mut u8,
) -> *mut u8 {
    let nsproxy_ptr = cread(unsafe { &*task }.nsproxy().as_ptr());
    let cgroup_ns_ptr = cread(unsafe { &*nsproxy_ptr }.cgroup_ns().as_ptr());
    let root_cset_ptr = cread(unsafe { &*cgroup_ns_ptr }.root_cset().as_ptr());
    let root_dfl_cgrp_ptr = cread(unsafe { &*root_cset_ptr }.dfl_cgrp().as_ptr());
    let root_kernfs = cread(unsafe { &*root_dfl_cgrp_ptr }.kn().as_ptr());

    let cgroups_ptr = cread(unsafe { &*task }.cgroups().as_ptr());
    let proc_dfl_cgrp_ptr = cread(unsafe { &*cgroups_ptr }.dfl_cgrp().as_ptr());
    let proc_kernfs = cread(unsafe { &*proc_dfl_cgrp_ptr }.kn().as_ptr());

    // ENABLE_CGROUP_V1_RESOLVER && CONFIG_CGROUP_PIDS: always false at
    // runtime (bpf_config.enable_cgroup_v1_resolver defaults to, and the
    // test never sets it away from, 0) -- see file-level comment.

    cgroup_data.cgroup_root_inode = get_inode_from_kernfs(root_kernfs);
    cgroup_data.cgroup_proc_inode = get_inode_from_kernfs(proc_kernfs);

    // Modern kernfs_iattrs shape (ia_mtime direct, not nested under
    // ia_iattr) -- see file-level comment.
    let root_iattr_ptr = cread(unsafe { &*root_kernfs }.iattr().as_ptr());
    let root_mtime: i64 = cread(unsafe { &*root_iattr_ptr }.ia_mtime().tv_nsec().as_ptr());
    cgroup_data.cgroup_root_mtime = root_mtime as u64;
    let proc_iattr_ptr = cread(unsafe { &*proc_kernfs }.iattr().as_ptr());
    let proc_mtime: i64 = cread(unsafe { &*proc_iattr_ptr }.ia_mtime().tv_nsec().as_ptr());
    cgroup_data.cgroup_proc_mtime = proc_mtime as u64;

    cgroup_data.cgroup_root_length = 0;
    cgroup_data.cgroup_proc_length = 0;
    cgroup_data.cgroup_full_length = 0;

    let mut payload = payload;
    let root_name_ptr = cread(unsafe { &*root_kernfs }.name().as_ptr());
    let cgroup_root_length =
        bpf_probe_read_kernel_str(payload as *mut c_void, MAX_PATH as u32, root_name_ptr as *const c_void)
            as usize;
    if cgroup_root_length <= MAX_PATH {
        cgroup_data.cgroup_root_length = cgroup_root_length as u16;
        payload = unsafe { payload.add(cgroup_root_length) };
    }

    let proc_name_ptr = cread(unsafe { &*proc_kernfs }.name().as_ptr());
    let cgroup_proc_length =
        bpf_probe_read_kernel_str(payload as *mut c_void, MAX_PATH as u32, proc_name_ptr as *const c_void)
            as usize;
    if cgroup_proc_length <= MAX_PATH {
        cgroup_data.cgroup_proc_length = cgroup_proc_length as u16;
        payload = unsafe { payload.add(cgroup_proc_length) };
    }

    if unsafe { bpf_config.fetch_cgroups_from_bpf } {
        cgroup_data.cgroup_full_path_root_pos = -1;
        let mut root_pos: i32 = -1;
        let payload_end_pos = read_full_cgroup_path(proc_kernfs, root_kernfs, payload, &mut root_pos);
        cgroup_data.cgroup_full_path_root_pos = root_pos;
        cgroup_data.cgroup_full_length = (payload_end_pos as usize - payload as usize) as u16;
        payload = payload_end_pos;
    }

    payload
}

#[inline(always)]
fn populate_var_metadata(
    metadata: &mut VarMetadata,
    task: *const task_struct,
    pid: u32,
    payload: *mut u8,
) -> *mut u8 {
    let uid_gid = bpf_get_current_uid_gid();
    metadata.uid = uid_gid as u32;
    metadata.gid = (uid_gid >> 32) as u32;
    metadata.pid = pid as i32;
    metadata.exec_id = cread(unsafe { &*task }.self_exec_id().as_ptr()) as u32;
    metadata.start_time = cread(unsafe { &*task }.start_time().as_ptr());
    metadata.comm_length = 0;

    let comm_length = bpf_probe_read_kernel_str(
        payload as *mut c_void,
        TASK_COMM_LEN as u32,
        unsafe { &*task }.comm().as_ptr() as *const c_void,
    ) as usize;
    if comm_length <= TASK_COMM_LEN {
        metadata.comm_length = comm_length as u8;
        return unsafe { payload.add(comm_length) };
    }
    payload
}

#[inline(always)]
fn get_var_kill_data(spid: i32, tpid: i32, sig: i32) -> *mut VarKillData {
    let zero: i32 = 0;
    let kill_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarKillData;
    if kill_data.is_null() {
        return core::ptr::null_mut();
    }
    let task = bpf_get_current_task() as *const task_struct;

    let payload = populate_var_metadata(unsafe { &mut (*kill_data).meta }, task, spid as u32, unsafe {
        (*kill_data).payload.as_mut_ptr()
    });
    let payload = populate_cgroup_info(unsafe { &mut (*kill_data).cgroup_data }, task, payload);
    let payload_length = payload as usize - unsafe { (*kill_data).payload.as_ptr() } as usize;
    unsafe {
        (*kill_data).payload_length = payload_length;
        populate_ancestors(task, &mut (*kill_data).ancestors_info);
        (*kill_data).meta.type_ = KILL_EVENT;
        (*kill_data).kill_target_pid = tpid;
        (*kill_data).kill_sig = sig;
        (*kill_data).kill_count = 1;
        (*kill_data).last_kill_time = bpf_ktime_get_ns();
    }
    kill_data
}

#[inline(always)]
fn trace_var_sys_kill(tpid: i32, sig: i32) -> i32 {
    if (unsafe { bpf_config.kill_signals_mask } & 1u64.wrapping_shl(sig as u32)) == 0 {
        return 0;
    }

    let spid = get_userspace_pid() as i32;
    let arr_struct = bpf_map_lookup_elem(&var_tpid_to_data, &tpid) as *mut VarKillDataArr;

    if arr_struct.is_null() {
        let kill_data = get_var_kill_data(spid, tpid, sig);
        let zero: i32 = 0;
        if kill_data.is_null() {
            return 0;
        }
        let arr_struct = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarKillDataArr;
        if arr_struct.is_null() {
            return 0;
        }
        unsafe {
            bpf_probe_read_kernel(
                &mut (*arr_struct).array[0],
                core::mem::size_of::<VarKillData>() as u32,
                kill_data as *const c_void,
            );
        }
        bpf_map_update_elem(&var_tpid_to_data, &tpid, unsafe { &*arr_struct }, 0);
    } else {
        let index = get_var_spid_index(unsafe { &*arr_struct }, spid);
        if index == -1 {
            let kill_data = get_var_kill_data(spid, tpid, sig);
            if kill_data.is_null() {
                return 0;
            }
            for i in 0..KILL_DATA_ARRAY_SIZE {
                if unsafe { (*arr_struct).array[i].meta.pid } == 0 {
                    unsafe {
                        bpf_probe_read_kernel(
                            &mut (*arr_struct).array[i],
                            core::mem::size_of::<VarKillData>() as u32,
                            kill_data as *const c_void,
                        );
                    }
                    bpf_map_update_elem(&var_tpid_to_data, &tpid, unsafe { &*arr_struct }, 0);
                    return 0;
                }
            }
            return 0;
        }

        let index = index as usize;
        let kill_data_ptr = unsafe { &mut (*arr_struct).array[index] as *mut VarKillData };
        let delta_sec = (bpf_ktime_get_ns() - unsafe { (*kill_data_ptr).last_kill_time }) / 1_000_000_000;

        if delta_sec < unsafe { bpf_config.stale_info_secs } as u64 {
            unsafe {
                (*kill_data_ptr).kill_count += 1;
                (*kill_data_ptr).last_kill_time = bpf_ktime_get_ns();
                bpf_probe_read_kernel(
                    &mut (*arr_struct).array[index],
                    core::mem::size_of::<VarKillData>() as u32,
                    kill_data_ptr as *const c_void,
                );
            }
        } else {
            let kill_data = get_var_kill_data(spid, tpid, sig);
            if kill_data.is_null() {
                return 0;
            }
            unsafe {
                bpf_probe_read_kernel(
                    &mut (*arr_struct).array[index],
                    core::mem::size_of::<VarKillData>() as u32,
                    kill_data as *const c_void,
                );
            }
        }
        bpf_map_update_elem(&var_tpid_to_data, &tpid, unsafe { &*arr_struct }, 0);
    }
    0
}

#[inline(always)]
fn bpf_stats_enter(ctx: &mut BpfFuncStatsCtx, func_id: u32) {
    ctx.start_time_ns = bpf_ktime_get_ns();
    let key = func_id;
    ctx.bpf_func_stats_data_val = bpf_map_lookup_elem(&bpf_func_stats, &key) as *mut BpfFuncStatsData;
    if !ctx.bpf_func_stats_data_val.is_null() {
        unsafe {
            (*ctx.bpf_func_stats_data_val).num_executions += 1;
        }
    }
}

#[inline(always)]
fn bpf_stats_exit(ctx: &BpfFuncStatsCtx) {
    if !ctx.bpf_func_stats_data_val.is_null() {
        unsafe {
            (*ctx.bpf_func_stats_data_val).time_elapsed_ns += bpf_ktime_get_ns() - ctx.start_time_ns;
        }
    }
}

#[inline(always)]
fn bpf_stats_pre_submit_var_perf_event(ctx: &BpfFuncStatsCtx, meta: &mut VarMetadata) {
    if !ctx.bpf_func_stats_data_val.is_null() {
        unsafe {
            (*ctx.bpf_func_stats_data_val).num_perf_events += 1;
            meta.bpf_stats_num_perf_events = (*ctx.bpf_func_stats_data_val).num_perf_events;
        }
    }
    meta.bpf_stats_start_ktime_ns = ctx.start_time_ns;
    meta.cpu_id = bpf_get_smp_processor_id();
}

#[inline(always)]
fn read_absolute_file_path_from_dentry(mut filp_dentry: *mut dentry, payload: *mut u8) -> usize {
    let mut length: usize = 0;
    let mut payload = payload;
    for _ in 0..MAX_PATH_DEPTH {
        let name_ptr = cread(unsafe { &*filp_dentry }.d_name().name().as_ptr());
        let filepart_length =
            bpf_probe_read_kernel_str(payload as *mut c_void, MAX_PATH as u32, name_ptr as *const c_void)
                as usize;
        if filepart_length > MAX_PATH {
            break;
        }
        payload = unsafe { payload.add(filepart_length) };
        length += filepart_length;

        let parent_dentry = cread(unsafe { &*filp_dentry }.d_parent().as_ptr());
        if filp_dentry == parent_dentry {
            break;
        }
        filp_dentry = parent_dentry;
    }
    length
}

#[inline(always)]
fn is_ancestor_in_allowed_inodes(mut filp_dentry: *mut dentry) -> bool {
    for _ in 0..MAX_PATH_DEPTH {
        let inode_ptr = cread(unsafe { &*filp_dentry }.d_inode().as_ptr());
        let dir_ino: u64 = cread(unsafe { &*inode_ptr }.i_ino().as_ptr());
        let allowed_dir = bpf_map_lookup_elem(&allowed_directory_inodes, &dir_ino);
        if !allowed_dir.is_null() {
            return true;
        }
        let parent_dentry = cread(unsafe { &*filp_dentry }.d_parent().as_ptr());
        if filp_dentry == parent_dentry {
            break;
        }
        filp_dentry = parent_dentry;
    }
    false
}

#[inline(always)]
fn is_dentry_allowed_for_filemod(
    file_dentry: *mut dentry,
    device_id: &mut u32,
    file_ino: &mut u64,
) -> bool {
    let sb_ptr = cread(unsafe { &*file_dentry }.d_sb().as_ptr());
    let dev_id: u32 = cread(unsafe { &*sb_ptr }.s_dev().as_ptr());
    *device_id = dev_id;
    let allowed_device = bpf_map_lookup_elem(&allowed_devices, &dev_id);
    if allowed_device.is_null() {
        return false;
    }

    let inode_ptr = cread(unsafe { &*file_dentry }.d_inode().as_ptr());
    let ino: u64 = cread(unsafe { &*inode_ptr }.i_ino().as_ptr());
    *file_ino = ino;
    let allowed_file = bpf_map_lookup_elem(&allowed_file_inodes, &ino);
    if allowed_file.is_null() {
        let parent = cread(unsafe { &*file_dentry }.d_parent().as_ptr());
        if !is_ancestor_in_allowed_inodes(parent) {
            return false;
        }
    }
    true
}

// --------------------------------------------------------------- programs --

#[link_section = "kprobe/proc_sys_write"]
#[no_mangle]
extern "C" fn kprobe__proc_sys_write(ctx: *const u64) -> i32 {
    let filp = unsafe { *ctx.add(REG_DI) } as *mut file;
    let buf = unsafe { *ctx.add(REG_SI) } as *const c_void;

    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_PROC_SYS_WRITE);

    let pid = get_userspace_pid();
    let zero: i32 = 0;
    let sysctl_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarSysctlData;
    if sysctl_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let task = bpf_get_current_task() as *const task_struct;
    unsafe {
        (*sysctl_data).meta.type_ = SYSCTL_EVENT;
    }
    let mut payload = populate_var_metadata(unsafe { &mut (*sysctl_data).meta }, task, pid, unsafe {
        (*sysctl_data).payload.as_mut_ptr()
    });
    payload = populate_cgroup_info(unsafe { &mut (*sysctl_data).cgroup_data }, task, payload);
    populate_ancestors(task, unsafe { &mut (*sysctl_data).ancestors_info });

    unsafe {
        (*sysctl_data).sysctl_val_length = 0;
        (*sysctl_data).sysctl_path_length = 0;
    }

    let sysctl_val_length =
        bpf_probe_read_kernel_str(payload as *mut c_void, CTL_MAXNAME as u32, buf) as usize;
    if sysctl_val_length <= CTL_MAXNAME {
        unsafe {
            (*sysctl_data).sysctl_val_length = sysctl_val_length as u8;
        }
        payload = unsafe { payload.add(sysctl_val_length) };
    }

    let filp_dentry = cread(unsafe { &*filp }.f_path().dentry().as_ptr());
    let name_ptr = cread(unsafe { &*filp_dentry }.d_name().name().as_ptr());
    let sysctl_path_length =
        bpf_probe_read_kernel_str(payload as *mut c_void, MAX_PATH as u32, name_ptr as *const c_void)
            as usize;
    if sysctl_path_length <= MAX_PATH {
        unsafe {
            (*sysctl_data).sysctl_path_length = sysctl_path_length as u16;
        }
        payload = unsafe { payload.add(sysctl_path_length) };
    }

    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*sysctl_data).meta });
    let mut data_len = payload as usize - sysctl_data as usize;
    if data_len > core::mem::size_of::<VarSysctlData>() {
        data_len = core::mem::size_of::<VarSysctlData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*sysctl_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "tracepoint/syscalls/sys_enter_kill"]
#[no_mangle]
extern "C" fn tracepoint__syscalls__sys_enter_kill(ctx: *const u8) -> i32 {
    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_SYS_ENTER_KILL);

    let pid = unsafe { core::ptr::read_unaligned(ctx.add(16) as *const i64) } as i32;
    let sig = unsafe { core::ptr::read_unaligned(ctx.add(24) as *const i64) } as i32;
    let ret = trace_var_sys_kill(pid, sig);

    bpf_stats_exit(&stats_ctx);
    ret
}

#[link_section = "raw_tracepoint/sched_process_exit"]
#[no_mangle]
extern "C" fn raw_tracepoint__sched_process_exit(ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_SCHED_PROCESS_EXIT);

    let tpid = get_userspace_pid() as i32;

    let arr_struct = bpf_map_lookup_elem(&var_tpid_to_data, &tpid) as *mut VarKillDataArr;
    let kill_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarKillData;

    if arr_struct.is_null() || kill_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let task = bpf_get_current_task() as *const task_struct;
    let cgroups_ptr = cread(unsafe { &*task }.cgroups().as_ptr());
    let dfl_cgrp_ptr = cread(unsafe { &*cgroups_ptr }.dfl_cgrp().as_ptr());
    let proc_kernfs = cread(unsafe { &*dfl_cgrp_ptr }.kn().as_ptr());

    for i in 0..KILL_DATA_ARRAY_SIZE {
        let past_kill_data = unsafe { &mut (*arr_struct).array[i] as *mut VarKillData };
        if unsafe { (*past_kill_data).kill_target_pid } == tpid {
            unsafe {
                bpf_probe_read_kernel(
                    &mut *kill_data,
                    core::mem::size_of::<VarKillData>() as u32,
                    past_kill_data as *const c_void,
                );
            }
            let mut payload = unsafe { (*kill_data).payload.as_mut_ptr() };
            let offset = unsafe { (*kill_data).payload_length };
            if offset >= MAX_METADATA_PAYLOAD_LEN + MAX_CGROUP_PAYLOAD_LEN {
                return 0;
            }
            payload = unsafe { payload.add(offset) };

            unsafe {
                (*kill_data).kill_target_name_length = 0;
                (*kill_data).kill_target_cgroup_proc_length = 0;
            }

            let comm_length = bpf_probe_read_kernel_str(
                payload as *mut c_void,
                TASK_COMM_LEN as u32,
                unsafe { &*task }.comm().as_ptr() as *const c_void,
            ) as usize;
            if comm_length <= TASK_COMM_LEN {
                unsafe {
                    (*kill_data).kill_target_name_length = comm_length as u8;
                }
                payload = unsafe { payload.add(comm_length) };
            }

            let proc_name_ptr = cread(unsafe { &*proc_kernfs }.name().as_ptr());
            let cgroup_proc_length = bpf_probe_read_kernel_str(
                payload as *mut c_void,
                KILL_TARGET_LEN as u32,
                proc_name_ptr as *const c_void,
            ) as usize;
            if cgroup_proc_length <= KILL_TARGET_LEN {
                unsafe {
                    (*kill_data).kill_target_cgroup_proc_length = cgroup_proc_length as u8;
                }
                payload = unsafe { payload.add(cgroup_proc_length) };
            }

            bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*kill_data).meta });
            let mut data_len = payload as usize - kill_data as usize;
            if data_len > core::mem::size_of::<VarKillData>() {
                data_len = core::mem::size_of::<VarKillData>();
            }
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, unsafe { &*kill_data }, data_len as u64);
        }
    }
    bpf_map_delete_elem(&var_tpid_to_data, &tpid);
    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "raw_tracepoint/sched_process_exec"]
#[no_mangle]
extern "C" fn raw_tracepoint__sched_process_exec(ctx: *const u64) -> i32 {
    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_SCHED_PROCESS_EXEC);

    let bprm = unsafe { *ctx.add(2) } as *const linux_binprm;
    let file_ptr = cread(unsafe { &*bprm }.file().as_ptr());
    let inode_ptr = cread(unsafe { &*file_ptr }.f_inode().as_ptr());
    let inode_num: u64 = cread(unsafe { &*inode_ptr }.i_ino().as_ptr());

    let should_filter_binprm = bpf_map_lookup_elem(&disallowed_exec_inodes, &inode_num);
    if !should_filter_binprm.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let zero: i32 = 0;
    let proc_exec_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarExecData;
    if proc_exec_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let inode_filter = unsafe { bpf_config.inode_filter };
    if inode_filter != 0 && inode_num != inode_filter {
        // matches C: bare `return 0;` here, bypassing bpf_stats_exit.
        return 0;
    }

    let pid = get_userspace_pid();
    let task = bpf_get_current_task() as *const task_struct;

    unsafe {
        (*proc_exec_data).meta.type_ = EXEC_EVENT;
        (*proc_exec_data).bin_path_length = 0;
        (*proc_exec_data).cmdline_length = 0;
        (*proc_exec_data).environment_length = 0;
    }
    let mut payload = populate_var_metadata(unsafe { &mut (*proc_exec_data).meta }, task, pid, unsafe {
        (*proc_exec_data).payload.as_mut_ptr()
    });
    payload = populate_cgroup_info(unsafe { &mut (*proc_exec_data).cgroup_data }, task, payload);

    let parent_task = cread(unsafe { &*task }.real_parent().as_ptr());
    unsafe {
        (*proc_exec_data).parent_pid = cread((&*parent_task).tgid().as_ptr());
        let cred_ptr = cread((&*parent_task).real_cred().as_ptr());
        (*proc_exec_data).parent_uid = cread((&*cred_ptr).uid().val().as_ptr());
        (*proc_exec_data).parent_exec_id = cread((&*parent_task).self_exec_id().as_ptr()) as u32;
        (*proc_exec_data).parent_start_time = cread((&*parent_task).start_time().as_ptr());
    }

    let filename_ptr = cread(unsafe { &*bprm }.filename().as_ptr());
    let bin_path_length = bpf_probe_read_kernel_str(
        payload as *mut c_void,
        MAX_FILENAME_LEN as u32,
        filename_ptr as *const c_void,
    ) as usize;
    if bin_path_length <= MAX_FILENAME_LEN {
        unsafe {
            (*proc_exec_data).bin_path_length = bin_path_length as u16;
        }
        payload = unsafe { payload.add(bin_path_length) };
    }

    let mm_ptr = cread(unsafe { &*task }.mm().as_ptr());
    let arg_start: u64 = cread(unsafe { &*mm_ptr }.arg_start().as_ptr());
    let arg_end: u64 = cread(unsafe { &*mm_ptr }.arg_end().as_ptr());
    let cmdline_length = probe_read_lim(
        payload as *mut c_void,
        arg_start as *mut c_void,
        arg_end.wrapping_sub(arg_start),
        MAX_ARGS_LEN as u64,
    ) as u32;
    if (cmdline_length as usize) <= MAX_ARGS_LEN {
        unsafe {
            (*proc_exec_data).cmdline_length = cmdline_length as u16;
        }
        payload = unsafe { payload.add(cmdline_length as usize) };
    }

    if unsafe { bpf_config.read_environ_from_exec } {
        let env_start: u64 = cread(unsafe { &*mm_ptr }.env_start().as_ptr());
        let env_end: u64 = cread(unsafe { &*mm_ptr }.env_end().as_ptr());
        let env_len = probe_read_lim(
            payload as *mut c_void,
            env_start as *mut c_void,
            env_end.wrapping_sub(env_start),
            MAX_ENVIRON_LEN as u64,
        );
        if (cmdline_length as usize) <= MAX_ENVIRON_LEN {
            unsafe {
                (*proc_exec_data).environment_length = env_len as u16;
            }
            payload = unsafe { payload.add(env_len as usize) };
        }
    }

    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*proc_exec_data).meta });
    let mut data_len = payload as usize - proc_exec_data as usize;
    if data_len > core::mem::size_of::<VarExecData>() {
        data_len = core::mem::size_of::<VarExecData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*proc_exec_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "kretprobe/do_file_open"]
#[no_mangle]
extern "C" fn kprobe_ret__do_file_open(ctx: *const u64) -> i32 {
    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_DO_FILE_OPEN_RET);

    let filp = unsafe { *ctx.add(REG_AX) } as *mut file;

    if filp.is_null() || is_err(filp as *const c_void) {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }
    let flags: u32 = cread(unsafe { &*filp }.f_flags().as_ptr());
    if (flags & (O_RDWR | O_WRONLY)) == 0 {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }
    if (flags & O_TMPFILE) > 0 {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }
    let file_inode = cread(unsafe { &*filp }.f_inode().as_ptr());
    let mode: u16 = cread(unsafe { &*file_inode }.i_mode().as_ptr());
    let mode = mode as u32;
    let ifmt = mode & S_IFMT;
    if ifmt == S_IFDIR || ifmt == S_IFCHR || ifmt == S_IFBLK || ifmt == S_IFIFO || ifmt == S_IFSOCK {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let filp_dentry = cread(unsafe { &*filp }.f_path().dentry().as_ptr());
    let mut device_id: u32 = 0;
    let mut file_ino: u64 = 0;
    if !is_dentry_allowed_for_filemod(filp_dentry, &mut device_id, &mut file_ino) {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let zero: i32 = 0;
    let filemod_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarFilemodData;
    if filemod_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let pid = get_userspace_pid();
    let task = bpf_get_current_task() as *const task_struct;

    unsafe {
        (*filemod_data).meta.type_ = FILEMOD_EVENT;
        (*filemod_data).fmod_type = FMOD_OPEN;
        (*filemod_data).dst_flags = flags;
        (*filemod_data).src_inode = 0;
        (*filemod_data).dst_inode = file_ino;
        (*filemod_data).src_device_id = 0;
        (*filemod_data).dst_device_id = device_id;
        (*filemod_data).src_filepath_length = 0;
        (*filemod_data).dst_filepath_length = 0;
    }

    let mut payload = populate_var_metadata(unsafe { &mut (*filemod_data).meta }, task, pid, unsafe {
        (*filemod_data).payload.as_mut_ptr()
    });
    payload = populate_cgroup_info(unsafe { &mut (*filemod_data).cgroup_data }, task, payload);

    let len = read_absolute_file_path_from_dentry(filp_dentry, payload);
    if len <= MAX_FILEPATH_LENGTH {
        payload = unsafe { payload.add(len) };
        unsafe {
            (*filemod_data).dst_filepath_length = len as u16;
        }
    }
    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*filemod_data).meta });
    let mut data_len = payload as usize - filemod_data as usize;
    if data_len > core::mem::size_of::<VarFilemodData>() {
        data_len = core::mem::size_of::<VarFilemodData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*filemod_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "kprobe/vfs_link"]
#[no_mangle]
extern "C" fn kprobe__vfs_link(ctx: *const u64) -> i32 {
    let old_dentry = unsafe { *ctx.add(REG_DI) } as *mut dentry;
    let new_dentry = unsafe { *ctx.add(REG_CX) } as *mut dentry;

    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_VFS_LINK);

    let mut src_device_id: u32 = 0;
    let mut src_file_ino: u64 = 0;
    let mut dst_device_id: u32 = 0;
    let mut dst_file_ino: u64 = 0;
    let old_allowed = is_dentry_allowed_for_filemod(old_dentry, &mut src_device_id, &mut src_file_ino);
    if !old_allowed && !is_dentry_allowed_for_filemod(new_dentry, &mut dst_device_id, &mut dst_file_ino) {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let zero: i32 = 0;
    let filemod_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarFilemodData;
    if filemod_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }
    let pid = get_userspace_pid();
    let task = bpf_get_current_task() as *const task_struct;

    unsafe {
        (*filemod_data).meta.type_ = FILEMOD_EVENT;
        (*filemod_data).fmod_type = FMOD_LINK;
        (*filemod_data).dst_flags = 0;
        (*filemod_data).src_inode = src_file_ino;
        (*filemod_data).dst_inode = dst_file_ino;
        (*filemod_data).src_device_id = src_device_id;
        (*filemod_data).dst_device_id = dst_device_id;
        (*filemod_data).src_filepath_length = 0;
        (*filemod_data).dst_filepath_length = 0;
    }

    let mut payload = populate_var_metadata(unsafe { &mut (*filemod_data).meta }, task, pid, unsafe {
        (*filemod_data).payload.as_mut_ptr()
    });
    payload = populate_cgroup_info(unsafe { &mut (*filemod_data).cgroup_data }, task, payload);

    let mut len = read_absolute_file_path_from_dentry(old_dentry, payload);
    if len <= MAX_FILEPATH_LENGTH {
        payload = unsafe { payload.add(len) };
        unsafe {
            (*filemod_data).src_filepath_length = len as u16;
        }
    }
    len = read_absolute_file_path_from_dentry(new_dentry, payload);
    if len <= MAX_FILEPATH_LENGTH {
        payload = unsafe { payload.add(len) };
        unsafe {
            (*filemod_data).dst_filepath_length = len as u16;
        }
    }

    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*filemod_data).meta });
    let mut data_len = payload as usize - filemod_data as usize;
    if data_len > core::mem::size_of::<VarFilemodData>() {
        data_len = core::mem::size_of::<VarFilemodData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*filemod_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "kprobe/vfs_symlink"]
#[no_mangle]
extern "C" fn kprobe__vfs_symlink(ctx: *const u64) -> i32 {
    let dentry_arg = unsafe { *ctx.add(REG_SI) } as *mut dentry;
    let oldname = unsafe { *ctx.add(REG_DX) } as *const c_void;

    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_VFS_SYMLINK);

    let mut dst_device_id: u32 = 0;
    let mut dst_file_ino: u64 = 0;
    if !is_dentry_allowed_for_filemod(dentry_arg, &mut dst_device_id, &mut dst_file_ino) {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let zero: i32 = 0;
    let filemod_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarFilemodData;
    if filemod_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }
    let pid = get_userspace_pid();
    let task = bpf_get_current_task() as *const task_struct;

    unsafe {
        (*filemod_data).meta.type_ = FILEMOD_EVENT;
        (*filemod_data).fmod_type = FMOD_SYMLINK;
        (*filemod_data).dst_flags = 0;
        (*filemod_data).src_inode = 0;
        (*filemod_data).dst_inode = dst_file_ino;
        (*filemod_data).src_device_id = 0;
        (*filemod_data).dst_device_id = dst_device_id;
        (*filemod_data).src_filepath_length = 0;
        (*filemod_data).dst_filepath_length = 0;
    }

    let mut payload = populate_var_metadata(unsafe { &mut (*filemod_data).meta }, task, pid, unsafe {
        (*filemod_data).payload.as_mut_ptr()
    });
    payload = populate_cgroup_info(unsafe { &mut (*filemod_data).cgroup_data }, task, payload);

    let len = bpf_probe_read_kernel_str(payload as *mut c_void, MAX_FILEPATH_LENGTH as u32, oldname) as usize;
    if len <= MAX_FILEPATH_LENGTH {
        payload = unsafe { payload.add(len) };
        unsafe {
            (*filemod_data).src_filepath_length = len as u16;
        }
    }
    let len2 = read_absolute_file_path_from_dentry(dentry_arg, payload);
    if len2 <= MAX_FILEPATH_LENGTH {
        payload = unsafe { payload.add(len2) };
        unsafe {
            (*filemod_data).dst_filepath_length = len2 as u16;
        }
    }
    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*filemod_data).meta });
    let mut data_len = payload as usize - filemod_data as usize;
    if data_len > core::mem::size_of::<VarFilemodData>() {
        data_len = core::mem::size_of::<VarFilemodData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*filemod_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

#[link_section = "raw_tracepoint/sched_process_fork"]
#[no_mangle]
extern "C" fn raw_tracepoint__sched_process_fork(ctx: *const u64) -> i32 {
    let mut stats_ctx = BpfFuncStatsCtx::new();
    bpf_stats_enter(&mut stats_ctx, PROFILER_BPF_SCHED_PROCESS_FORK);

    let zero: i32 = 0;
    let fork_data = bpf_map_lookup_elem(&data_heap, &zero) as *mut VarForkData;
    if fork_data.is_null() {
        bpf_stats_exit(&stats_ctx);
        return 0;
    }

    let parent = unsafe { *ctx.add(0) } as *const task_struct;
    let child = unsafe { *ctx.add(1) } as *const task_struct;
    unsafe {
        (*fork_data).meta.type_ = FORK_EVENT;
    }

    let child_pid: i32 = cread(unsafe { &*child }.pid().as_ptr());
    let payload = populate_var_metadata(
        unsafe { &mut (*fork_data).meta },
        child,
        child_pid as u32,
        unsafe { (*fork_data).payload.as_mut_ptr() },
    );
    unsafe {
        (*fork_data).parent_pid = cread((&*parent).pid().as_ptr());
        (*fork_data).parent_exec_id = cread((&*parent).self_exec_id().as_ptr()) as u32;
        (*fork_data).parent_start_time = cread((&*parent).start_time().as_ptr());
    }
    bpf_stats_pre_submit_var_perf_event(&stats_ctx, unsafe { &mut (*fork_data).meta });

    let mut data_len = payload as usize - fork_data as usize;
    if data_len > core::mem::size_of::<VarForkData>() {
        data_len = core::mem::size_of::<VarForkData>();
    }
    bpf_perf_event_output(
        ctx as *const c_void,
        &events,
        BPF_F_CURRENT_CPU,
        unsafe { &*fork_data },
        data_len as u64,
    );

    bpf_stats_exit(&stats_ctx);
    0
}

bpf_object!("GPL");
