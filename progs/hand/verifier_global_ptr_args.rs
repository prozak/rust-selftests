// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_global_ptr_args.c, translated
// by hand; include!d by the generated progs/verifier_global_ptr_args.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_copy_from_user_task, bpf_get_current_task_btf, bpf_skb_pull_data};
use btf_macros::btf;

// bpf_core_cast(0, struct task_struct) / (0, struct bpf_verifier_env):
// bpf_rdonly_cast with the kernel type id (a CO-RE relocation each)
// BTF_TYPE_ID: task_struct_id struct task_struct
// BTF_TYPE_ID: bpf_verifier_env_id struct bpf_verifier_env
extern "C" {
    fn task_struct_id() -> u64;
    fn bpf_verifier_env_id() -> u64;
}

/// The kernel's task_struct, the fields read, with CO-RE; the name is what
/// the verifier matches a global subprogram's trusted/untrusted argument by.
#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
    prio: i32,
}

/// `enum bpf_attach_type` (uapi), for subprog_enum_untrusted's argument type.
#[allow(non_camel_case_types, dead_code)]
#[repr(u32)]
enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS = 0,
    BPF_CGROUP_INET_EGRESS = 1,
}

// HAND: subprog_trusted_task_nullable -- translate the C below (see the file comment)
//   __weak int subprog_trusted_task_nullable(struct task_struct *task __arg_trusted __arg_nullable)
//   {
//       if (!task)
//           return 0;
//       return task->pid + task->tgid;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_trusted_task_nullable(task: *mut task_struct) -> i32 {
    if task.is_null() {
        return 0;
    }
    let t = unsafe { &*task };
    (*t.pid().get().unwrap()).wrapping_add(*t.tgid().get().unwrap())
}

// HAND: subprog_trusted_task_nullable_extra_layer -- translate the C below (see the file comment)
//   __weak int subprog_trusted_task_nullable_extra_layer(struct task_struct *task __arg_trusted __arg_nullable)
//   {
//       return subprog_trusted_task_nullable(task) + subprog_trusted_task_nullable(NULL);
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_trusted_task_nullable_extra_layer(task: *mut task_struct) -> i32 {
    subprog_trusted_task_nullable(task).wrapping_add(subprog_trusted_task_nullable(core::ptr::null_mut()))
}

// HAND: trusted_task_arg_nullable -- translate the C below (see the file comment)
//   SEC("?tp_btf/task_newtask")
//   __success __log_level(2)
//   __msg("Validating subprog_trusted_task_nullable() func#1...")
//   __msg(": R1=trusted_ptr_or_null_task_struct(")
//   int trusted_task_arg_nullable(void *ctx)
//   {
//       struct task_struct *t1 = bpf_get_current_task_btf();
//       struct task_struct *t2 = bpf_task_acquire(t1);
//       int res = 0;
//
//       /* known NULL */
//       res += subprog_trusted_task_nullable(NULL);
//
//       /* known non-NULL */
//       res += subprog_trusted_task_nullable(t1);
//       res += subprog_trusted_task_nullable_extra_layer(t1);
//
//       /* unknown if NULL or not */
//       res += subprog_trusted_task_nullable(t2);
//       res += subprog_trusted_task_nullable_extra_layer(t2);
//
//       if (t2) {
//           /* known non-NULL after explicit NULL check, just in case */
//           res += subprog_trusted_task_nullable(t2);
//           res += subprog_trusted_task_nullable_extra_layer(t2);
//
//           bpf_task_release(t2);
//       }
//
//       return res;
//   }
#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trusted_task_arg_nullable(_ctx: *mut c_void) -> i32 {
    let t1: *mut task_struct = bpf_get_current_task_btf();
    let t2 = unsafe { bpf_task_acquire(t1 as *mut c_void) } as *mut task_struct;
    let mut res: i32 = 0;

    // known NULL
    res = res.wrapping_add(subprog_trusted_task_nullable(core::ptr::null_mut()));

    // known non-NULL
    res = res.wrapping_add(subprog_trusted_task_nullable(t1));
    res = res.wrapping_add(subprog_trusted_task_nullable_extra_layer(t1));

    // unknown if NULL or not
    res = res.wrapping_add(subprog_trusted_task_nullable(t2));
    res = res.wrapping_add(subprog_trusted_task_nullable_extra_layer(t2));

    if !t2.is_null() {
        // known non-NULL after explicit NULL check, just in case
        res = res.wrapping_add(subprog_trusted_task_nullable(t2));
        res = res.wrapping_add(subprog_trusted_task_nullable_extra_layer(t2));

        unsafe { bpf_task_release(t2 as *mut c_void) };
    }

    res
}

// HAND: subprog_trusted_task_nonnull -- translate the C below (see the file comment)
//   __weak int subprog_trusted_task_nonnull(struct task_struct *task __arg_trusted)
//   {
//       return task->pid + task->tgid;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_trusted_task_nonnull(task: *mut task_struct) -> i32 {
    let t = unsafe { &*task };
    (*t.pid().get().unwrap()).wrapping_add(*t.tgid().get().unwrap())
}

// HAND: trusted_task_arg_nonnull_fail1 -- translate the C below (see the file comment)
//   SEC("?kprobe")
//   __failure __log_level(2)
//   __msg("Possibly NULL pointer passed to trusted R1")
//   __msg("Caller passes invalid args into func#1 ('subprog_trusted_task_nonnull')")
//   int trusted_task_arg_nonnull_fail1(void *ctx)
//   {
//       return subprog_trusted_task_nonnull(NULL);
//   }
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn trusted_task_arg_nonnull_fail1(_ctx: *mut c_void) -> i32 {
    subprog_trusted_task_nonnull(core::ptr::null_mut())
}

// HAND: trusted_task_arg_nonnull_fail2 -- translate the C below (see the file comment)
//   SEC("?tp_btf/task_newtask")
//   __failure __log_level(2)
//   __msg("Possibly NULL pointer passed to trusted R1")
//   __msg("Caller passes invalid args into func#1 ('subprog_trusted_task_nonnull')")
//   int trusted_task_arg_nonnull_fail2(void *ctx)
//   {
//       struct task_struct *t = bpf_get_current_task_btf();
//       struct task_struct *nullable;
//       int res;
//
//       nullable = bpf_task_acquire(t);
//
//        /* should fail, PTR_TO_BTF_ID_OR_NULL */
//       res = subprog_trusted_task_nonnull(nullable);
//
//       if (nullable)
//           bpf_task_release(nullable);
//
//       return res;
//   }
#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trusted_task_arg_nonnull_fail2(_ctx: *mut c_void) -> i32 {
    let t: *mut task_struct = bpf_get_current_task_btf();
    let nullable = unsafe { bpf_task_acquire(t as *mut c_void) } as *mut task_struct;

    // should fail, PTR_TO_BTF_ID_OR_NULL
    let res = subprog_trusted_task_nonnull(nullable);

    if !nullable.is_null() {
        unsafe { bpf_task_release(nullable as *mut c_void) };
    }

    res
}

// HAND: trusted_task_arg_nonnull -- translate the C below (see the file comment)
//   SEC("?kprobe")
//   __success __log_level(2)
//   __msg("Validating subprog_trusted_task_nonnull() func#1...")
//   __msg(": R1=trusted_ptr_task_struct(")
//   int trusted_task_arg_nonnull(void *ctx)
//   {
//       struct task_struct *t = bpf_get_current_task_btf();
//
//       return subprog_trusted_task_nonnull(t);
//   }
#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn trusted_task_arg_nonnull(_ctx: *mut c_void) -> i32 {
    let t: *mut task_struct = bpf_get_current_task_btf();
    subprog_trusted_task_nonnull(t)
}

// HAND: subprog_nullable_task_flavor -- translate the C below (see the file comment)
//   __weak int subprog_nullable_task_flavor(
//       struct task_struct___local *task __arg_trusted __arg_nullable)
//   {
//       char buf[16];
//
//       if (!task)
//           return 0;
//
//       return bpf_copy_from_user_task(&buf, sizeof(buf), NULL, (void *)task, 0);
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_nullable_task_flavor(task: *mut task_struct___local) -> i32 {
    let mut buf = core::mem::MaybeUninit::<[i8; 16]>::uninit();
    if task.is_null() {
        return 0;
    }
    bpf_copy_from_user_task(buf.as_mut_ptr() as *mut c_void, 16, core::ptr::null(), task as *mut c_void, 0) as i32
}

// HAND: flavor_ptr_nullable -- translate the C below (see the file comment)
//   SEC("?uprobe.s")
//   __success __log_level(2)
//   __msg("Validating subprog_nullable_task_flavor() func#1...")
//   __msg(": R1=trusted_ptr_or_null_task_struct(")
//   int flavor_ptr_nullable(void *ctx)
//   {
//       struct task_struct___local *t = (void *)bpf_get_current_task_btf();
//
//       return subprog_nullable_task_flavor(t);
//   }
#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn flavor_ptr_nullable(_ctx: *mut c_void) -> i32 {
    let t: *mut task_struct___local = bpf_get_current_task_btf();
    subprog_nullable_task_flavor(t)
}

// HAND: subprog_nonnull_task_flavor -- translate the C below (see the file comment)
//   __weak int subprog_nonnull_task_flavor(struct task_struct___local *task __arg_trusted)
//   {
//       char buf[16];
//
//       return bpf_copy_from_user_task(&buf, sizeof(buf), NULL, (void *)task, 0);
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_nonnull_task_flavor(task: *mut task_struct___local) -> i32 {
    let mut buf = core::mem::MaybeUninit::<[i8; 16]>::uninit();
    bpf_copy_from_user_task(buf.as_mut_ptr() as *mut c_void, 16, core::ptr::null(), task as *mut c_void, 0) as i32
}

// HAND: flavor_ptr_nonnull -- translate the C below (see the file comment)
//   SEC("?uprobe.s")
//   __success __log_level(2)
//   __msg("Validating subprog_nonnull_task_flavor() func#1...")
//   __msg(": R1=trusted_ptr_task_struct(")
//   int flavor_ptr_nonnull(void *ctx)
//   {
//       struct task_struct *t = bpf_get_current_task_btf();
//
//       return subprog_nonnull_task_flavor((void *)t);
//   }
#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn flavor_ptr_nonnull(_ctx: *mut c_void) -> i32 {
    let t: *mut task_struct = bpf_get_current_task_btf();
    subprog_nonnull_task_flavor(t as *mut task_struct___local)
}

// HAND: subprog_trusted_destroy -- translate the C below (see the file comment)
//   __weak int subprog_trusted_destroy(struct task_struct *task __arg_trusted)
//   {
//       bpf_task_release(task); /* should be rejected */
//
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_trusted_destroy(task: *mut task_struct) -> i32 {
    unsafe { bpf_task_release(task as *mut c_void) }; // should be rejected
    0
}

// HAND: trusted_destroy_fail -- translate the C below (see the file comment)
//   SEC("?tp_btf/task_newtask")
//   __failure __log_level(2)
//   __msg("release function bpf_task_release expects referenced PTR_TO_BTF_ID passed to R1")
//   int BPF_PROG(trusted_destroy_fail, struct task_struct *task, u64 clone_flags)
//   {
//       return subprog_trusted_destroy(task);
//   }
// BPF_PROG(trusted_destroy_fail, struct task_struct *task, u64 clone_flags)
#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trusted_destroy_fail(ctx: *mut u64) -> i32 {
    let task = unsafe { *ctx } as *mut task_struct;
    subprog_trusted_destroy(task)
}

// HAND: subprog_trusted_acq_rel -- translate the C below (see the file comment)
//   __weak int subprog_trusted_acq_rel(struct task_struct *task __arg_trusted)
//   {
//       struct task_struct *owned;
//
//       owned = bpf_task_acquire(task);
//       if (!owned)
//           return 0;
//
//       bpf_task_release(owned); /* this one is OK, we acquired it locally */
//
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_trusted_acq_rel(task: *mut task_struct) -> i32 {
    let owned = unsafe { bpf_task_acquire(task as *mut c_void) };
    if owned.is_null() {
        return 0;
    }
    unsafe { bpf_task_release(owned) }; // this one is OK, we acquired it locally
    0
}

// HAND: trusted_acq_rel -- translate the C below (see the file comment)
//   SEC("?tp_btf/task_newtask")
//   __success __log_level(2)
//   int BPF_PROG(trusted_acq_rel, struct task_struct *task, u64 clone_flags)
//   {
//       return subprog_trusted_acq_rel(task);
//   }
// BPF_PROG(trusted_acq_rel, struct task_struct *task, u64 clone_flags)
#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trusted_acq_rel(ctx: *mut u64) -> i32 {
    let task = unsafe { *ctx } as *mut task_struct;
    subprog_trusted_acq_rel(task)
}

// HAND: subprog_untrusted_bad_tags -- translate the C below (see the file comment)
//   __weak int subprog_untrusted_bad_tags(struct task_struct *task __arg_untrusted __arg_nullable)
//   {
//       return task->pid;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_untrusted_bad_tags(task: *mut task_struct) -> i32 {
    *unsafe { &*task }.pid().get().unwrap()
}

// HAND: untrusted_bad_tags -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __failure
//   __msg("arg#0 untrusted cannot be combined with any other tags")
//   int untrusted_bad_tags(void *ctx)
//   {
//       return subprog_untrusted_bad_tags(0);
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn untrusted_bad_tags(_ctx: *mut c_void) -> i32 {
    subprog_untrusted_bad_tags(core::ptr::null_mut())
}

// HAND: subprog_untrusted_bad_type -- translate the C below (see the file comment)
//   __weak int subprog_untrusted_bad_type(struct local_type_wont_be_accepted *p __arg_untrusted)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_untrusted_bad_type(_p: *mut local_type_wont_be_accepted) -> i32 {
    0
}

// HAND: untrusted_bad_type -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __failure
//   __msg("arg#0 reference type('STRUCT local_type_wont_be_accepted') has no matches")
//   int untrusted_bad_type(void *ctx)
//   {
//       return subprog_untrusted_bad_type(bpf_rdonly_cast(0, 0));
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn untrusted_bad_type(_ctx: *mut c_void) -> i32 {
    subprog_untrusted_bad_type(unsafe { bpf_rdonly_cast(core::ptr::null_mut(), 0) } as *mut local_type_wont_be_accepted)
}

// HAND: subprog_untrusted -- translate the C below (see the file comment)
//   __weak int subprog_untrusted(const volatile struct task_struct *restrict task __arg_untrusted)
//   {
//       return task->pid;
//   }
// `const volatile struct task_struct *restrict task __arg_untrusted`
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_untrusted(task: *const task_struct) -> i32 {
    *unsafe { &*task }.pid().get().unwrap()
}

// HAND: trusted_to_untrusted -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __success
//   __log_level(2)
//   __msg("r1 = {{.*}}; {{.*}}R1=trusted_ptr_task_struct()")
//   __msg("Func#1 ('subprog_untrusted') is global and assumed valid.")
//   __msg("Validating subprog_untrusted() func#1...")
//   __msg(": R1=untrusted_ptr_task_struct")
//   int trusted_to_untrusted(void *ctx)
//   {
//       return subprog_untrusted(bpf_get_current_task_btf());
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn trusted_to_untrusted(_ctx: *mut c_void) -> i32 {
    subprog_untrusted(bpf_get_current_task_btf::<task_struct>())
}

// HAND: anything_to_untrusted -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __success
//   int anything_to_untrusted(void *ctx)
//   {
//       /* untrusted to untrusted */
//       subprog_untrusted(bpf_core_cast(0, struct task_struct));
//       /* wrong type to untrusted */
//       subprog_untrusted((void *)bpf_core_cast(0, struct bpf_verifier_env));
//       /* map value to untrusted */
//       subprog_untrusted((void *)mem);
//       /* scalar to untrusted */
//       subprog_untrusted(0);
//       /* variable offset to untrusted (map) */
//       subprog_untrusted((void *)mem + offset);
//       /* variable offset to untrusted (trusted) */
//       subprog_untrusted((void *)bpf_get_current_task_btf() + offset);
//       return 0;
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn anything_to_untrusted(_ctx: *mut c_void) -> i32 {
    unsafe {
        // untrusted to untrusted: bpf_core_cast(0, struct task_struct)
        subprog_untrusted(bpf_rdonly_cast(core::ptr::null_mut(), task_struct_id() as u32) as *const task_struct);
        // wrong type to untrusted
        subprog_untrusted(bpf_rdonly_cast(core::ptr::null_mut(), bpf_verifier_env_id() as u32) as *const task_struct);
        // map value to untrusted
        subprog_untrusted(core::ptr::addr_of_mut!(mem) as *const task_struct);
        // scalar to untrusted
        subprog_untrusted(core::ptr::null());
        // variable offset to untrusted (map)
        subprog_untrusted((core::ptr::addr_of_mut!(mem) as *mut u8).add(offset as usize) as *const task_struct);
        // variable offset to untrusted (trusted)
        subprog_untrusted((bpf_get_current_task_btf::<task_struct>() as *mut u8).add(offset as usize) as *const task_struct);
    }
    0
}

// HAND: subprog_untrusted2 -- translate the C below (see the file comment)
//   __weak int subprog_untrusted2(struct task_struct *task __arg_untrusted)
//   {
//       return subprog_trusted_task_nullable(task);
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_untrusted2(task: *mut task_struct) -> i32 {
    subprog_trusted_task_nullable(task)
}

// HAND: untrusted_to_trusted -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __failure
//   __msg("R1 type=untrusted_ptr_ expected=ptr_, trusted_ptr_, rcu_ptr_")
//   __msg("Caller passes invalid args into func#{{.*}} ('subprog_trusted_task_nullable')")
//   int untrusted_to_trusted(void *ctx)
//   {
//       return subprog_untrusted2(bpf_get_current_task_btf());
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn untrusted_to_trusted(_ctx: *mut c_void) -> i32 {
    subprog_untrusted2(bpf_get_current_task_btf::<task_struct>())
}

// HAND: subprog_void_untrusted -- translate the C below (see the file comment)
//   __weak int subprog_void_untrusted(void *p __arg_untrusted)
//   {
//       return *(int *)p;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_void_untrusted(p: *mut c_void) -> i32 {
    unsafe { *(p as *mut i32) }
}

// HAND: subprog_char_untrusted -- translate the C below (see the file comment)
//   __weak int subprog_char_untrusted(char *p __arg_untrusted)
//   {
//       return *(int *)p;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_char_untrusted(p: *mut i8) -> i32 {
    unsafe { *(p as *mut i32) }
}

// HAND: subprog_enum_untrusted -- translate the C below (see the file comment)
//   __weak int subprog_enum_untrusted(enum bpf_attach_type *p __arg_untrusted)
//   {
//       return *(int *)p;
//   }
// `enum bpf_attach_type *p`
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_enum_untrusted(p: *mut bpf_attach_type) -> i32 {
    unsafe { *(p as *mut i32) }
}

// HAND: trusted_to_untrusted_mem -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __success
//   __log_level(2)
//   __msg("r1 = {{.*}}; {{.*}}R1=trusted_ptr_task_struct()")
//   __msg("Func#1 ('subprog_void_untrusted') is global and assumed valid.")
//   __msg("Validating subprog_void_untrusted() func#1...")
//   __msg(": R1=rdonly_untrusted_mem(sz=0)")
//   int trusted_to_untrusted_mem(void *ctx)
//   {
//       return subprog_void_untrusted(bpf_get_current_task_btf());
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn trusted_to_untrusted_mem(_ctx: *mut c_void) -> i32 {
    subprog_void_untrusted(bpf_get_current_task_btf::<c_void>())
}

// HAND: subprog_write_mem_arg -- translate the C below (see the file comment)
//   __weak int subprog_write_mem_arg(int *p)
//   {
//       if (!p)
//           return 0;
//
//       *p = 42;
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_write_mem_arg(p: *mut i32) -> i32 {
    if p.is_null() {
        return 0;
    }
    unsafe { *p = 42 };
    0
}

// HAND: trusted_btf_field_to_writable_mem -- translate the C below (see the file comment)
//   SEC("?tp_btf/task_newtask")
//   __failure
//   __msg("only read is supported")
//   int trusted_btf_field_to_writable_mem(void *ctx)
//   {
//       struct task_struct *task = bpf_get_current_task_btf();
//
//       return subprog_write_mem_arg(&task->prio);
//   }
#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trusted_btf_field_to_writable_mem(_ctx: *mut c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    // &task->prio: the field's address through CO-RE
    subprog_write_mem_arg(unsafe { &*task }.prio().as_mut_ptr())
}

// HAND: anything_to_untrusted_mem -- translate the C below (see the file comment)
//   SEC("tp_btf/sys_enter")
//   __success
//   int anything_to_untrusted_mem(void *ctx)
//   {
//       /* untrusted to untrusted mem */
//       subprog_void_untrusted(bpf_core_cast(0, struct task_struct));
//       /* map value to untrusted mem */
//       subprog_void_untrusted(mem);
//       /* scalar to untrusted mem */
//       subprog_void_untrusted(0);
//       /* variable offset to untrusted mem (map) */
//       subprog_void_untrusted((void *)mem + offset);
//       /* variable offset to untrusted mem (trusted) */
//       subprog_void_untrusted(bpf_get_current_task_btf() + offset);
//       /* variable offset to untrusted char/enum (map) */
//       subprog_char_untrusted(mem + offset);
//       subprog_enum_untrusted((void *)mem + offset);
//       return 0;
//   }
#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn anything_to_untrusted_mem(_ctx: *mut c_void) -> i32 {
    unsafe {
        // untrusted to untrusted mem: bpf_core_cast(0, struct task_struct)
        subprog_void_untrusted(bpf_rdonly_cast(core::ptr::null_mut(), task_struct_id() as u32));
        // map value to untrusted mem
        subprog_void_untrusted(core::ptr::addr_of_mut!(mem) as *mut c_void);
        // scalar to untrusted mem
        subprog_void_untrusted(core::ptr::null_mut());
        // variable offset to untrusted mem (map)
        subprog_void_untrusted((core::ptr::addr_of_mut!(mem) as *mut u8).add(offset as usize) as *mut c_void);
        // variable offset to untrusted mem (trusted): `task + offset` scales
        // by sizeof(struct task_struct), 0x1880 in the C object
        subprog_void_untrusted((bpf_get_current_task_btf::<u8>()).add(offset as usize * 0x1880) as *mut c_void);
        // variable offset to untrusted char/enum (map)
        subprog_char_untrusted((core::ptr::addr_of_mut!(mem) as *mut i8).add(offset as usize));
        subprog_enum_untrusted((core::ptr::addr_of_mut!(mem) as *mut u8).add(offset as usize) as *mut bpf_attach_type);
    }
    0
}

// HAND: subprog_pkt_ptr_no_change -- translate the C below (see the file comment)
//   __weak int subprog_pkt_ptr_no_change(struct pkt_arg *p)
//   {
//       if (!p)
//           return 0;
//
//       return p->x;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_pkt_ptr_no_change(p: *mut pkt_arg) -> i32 {
    if p.is_null() {
        return 0;
    }
    unsafe { (*p).x as i32 }
}

// HAND: pkt_ptr_to_global_mem_arg_no_change -- translate the C below (see the file comment)
//   SEC("?tc")
//   __success
//   int pkt_ptr_to_global_mem_arg_no_change(struct __sk_buff *skb)
//   {
//       void *data = (void *)(long)skb->data;
//       void *data_end = (void *)(long)skb->data_end;
//       struct pkt_arg *p = data;
//
//       if ((void *)(p + 1) > data_end)
//           return 0;
//
//       return subprog_pkt_ptr_no_change(p);
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn pkt_ptr_to_global_mem_arg_no_change(skb: *mut __sk_buff) -> i32 {
    let data = unsafe { (*skb).data } as usize;
    let data_end = unsafe { (*skb).data_end } as usize;
    let p = data as *mut pkt_arg;

    if unsafe { p.add(1) } as usize > data_end {
        return 0;
    }

    subprog_pkt_ptr_no_change(p)
}

// HAND: subprog_pkt_ptr_changes_data -- translate the C below (see the file comment)
//   __weak int subprog_pkt_ptr_changes_data(struct __sk_buff *skb __arg_ctx,
//                       struct pkt_arg *p)
//   {
//       if (!p)
//           return 0;
//
//       bpf_skb_pull_data(skb, 0);
//       return p->x;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn subprog_pkt_ptr_changes_data(skb: *mut __sk_buff, p: *mut pkt_arg) -> i32 {
    if p.is_null() {
        return 0;
    }
    bpf_skb_pull_data(skb as *const c_void, 0);
    unsafe { (*p).x as i32 }
}

// HAND: pkt_ptr_to_global_mem_arg_changes_data -- translate the C below (see the file comment)
//   SEC("?tc")
//   __failure __log_level(2)
//   __msg("cannot pass packet pointer R2")
//   __msg("function may change packet data")
//   __msg("Caller passes invalid args into func#{{[0-9]+}} ('subprog_pkt_ptr_changes_data')")
//   int pkt_ptr_to_global_mem_arg_changes_data(struct __sk_buff *skb)
//   {
//       void *data = (void *)(long)skb->data;
//       void *data_end = (void *)(long)skb->data_end;
//       struct pkt_arg *p = data;
//
//       if ((void *)(p + 1) > data_end)
//           return 0;
//
//       return subprog_pkt_ptr_changes_data(skb, p);
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn pkt_ptr_to_global_mem_arg_changes_data(skb: *mut __sk_buff) -> i32 {
    let data = unsafe { (*skb).data } as usize;
    let data_end = unsafe { (*skb).data_end } as usize;
    let p = data as *mut pkt_arg;

    if unsafe { p.add(1) } as usize > data_end {
        return 0;
    }

    subprog_pkt_ptr_changes_data(skb, p)
}
