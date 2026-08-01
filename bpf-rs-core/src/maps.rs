// BPF map definitions. libbpf reads maps purely from BTF: a VAR in DATASEC
// ".maps" whose struct members encode parameters as pointer types
// (`__uint(type, V)` = `int (*type)[V]`, `__type(key, T)` = `T *key`). The
// generic below reaches BTF with exactly that member shape (verified
// byte-identical to the clang object, and the mangled struct name
// `BpfMap<...>` is accepted by the kernel — only VAR/member names are
// identifier-checked). Use `bpf_map!` for member sets the generic doesn't
// cover (pinning, key_size/value_size, absent max_entries, ...).

/// enum bpf_map_type values used as the TYPE parameter.
pub const HASH: usize = 1;
pub const ARRAY: usize = 2;
pub const PROG_ARRAY: usize = 3;
pub const PERF_EVENT_ARRAY: usize = 4;
pub const PERCPU_HASH: usize = 5;
pub const PERCPU_ARRAY: usize = 6;
pub const STACK_TRACE: usize = 7;
pub const LRU_HASH: usize = 9;
pub const LRU_PERCPU_HASH: usize = 10;
pub const RINGBUF: usize = 27;

/// The common map shape: type + max_entries + key + value.
///
/// ```ignore
/// #[link_section = ".maps"]
/// #[no_mangle]
/// static hash_map: BpfMap<u64, u64, { maps::HASH }, 2> = BpfMap::new();
/// ```
#[repr(C)]
pub struct BpfMap<K, V, const TYPE: usize, const MAX: usize> {
    r#type: *const [i32; TYPE],
    max_entries: *const [i32; MAX],
    key: *const K,
    value: *const V,
}

unsafe impl<K, V, const TYPE: usize, const MAX: usize> Sync for BpfMap<K, V, TYPE, MAX> {}

impl<K, V, const TYPE: usize, const MAX: usize> BpfMap<K, V, TYPE, MAX> {
    pub const fn new() -> Self {
        BpfMap {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
        }
    }
}

/// Escape hatch for map shapes the generic doesn't cover: declares the def
/// struct (members in source order become BTF members in order), the Sync
/// impl, and the null-initialized static in ".maps".
///
/// ```ignore
/// bpf_map! {
///     /// PERF_EVENT_ARRAY sized by libbpf (no max_entries member).
///     perf_buf_map {
///         r#type: *const [i32; maps::PERF_EVENT_ARRAY],
///         key: *const i32,
///         value: *const i32,
///     }
/// }
/// ```
#[macro_export]
macro_rules! bpf_map {
    ($(#[$doc:meta])* $name:ident { $($field:ident : $fty:ty),+ $(,)? }) => {
        // Type and value namespaces are separate: the def struct reuses the
        // map's own name, so no extra identifier is introduced. (The C
        // original's def struct is anonymous; map def struct names are not
        // load-bearing for libbpf.)
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct $name {
            $($field: $fty),+
        }
        unsafe impl Sync for $name {}
        #[link_section = ".maps"]
        #[no_mangle]
        $(#[$doc])*
        static $name: $name = $name {
            // every encoded member is a pointer (__uint/__type encoding)
            $($field: core::ptr::null()),+
        };
    };
}
