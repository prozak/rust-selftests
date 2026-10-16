"""Hermetic tests for __kconfig externs (#8): kconfig.py fills them the way
libbpf does, and the executor loads that value instead of bailing.

No kernel tree: the config is given inline.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import kconfig  # noqa: E402
from bpfsym import Bail  # noqa: E402
from kconfig import Kconfig, KconfigError  # noqa: E402
from testkit import asm, compare  # noqa: E402

R0, R1 = 0, 1

CONFIG = kconfig.parse_config("""\
CONFIG_HZ=1000
CONFIG_CGROUP_PIDS=y
CONFIG_MOD=m
# CONFIG_PREEMPT_RT is not set
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_NAME="bpf-next"
CONFIG_HEX=0x10
CONFIG_OCT=010
""")
KC = Kconfig(CONFIG, version=(7 << 16) + (2 << 8))

BOOL, TRI, CHAR = ("bool", 1, False), ("tristate", 4, False), ("char", 1, True)
INT, U8, I8 = ("int", 4, True), ("char", 1, False), ("char", 1, True)


# --- libbpf's encoding ------------------------------------------------------

@pytest.mark.parametrize("name,decl,weak,want", [
    ("CONFIG_HZ", INT, False, (1000).to_bytes(4, "little")),
    ("CONFIG_HEX", INT, False, (16).to_bytes(4, "little")),
    ("CONFIG_OCT", INT, False, (8).to_bytes(4, "little")),   # strtoull base 0
    ("CONFIG_CGROUP_PIDS", BOOL, True, b"\x01"),
    ("CONFIG_CGROUP_PIDS", TRI, False, (1).to_bytes(4, "little")),
    ("CONFIG_MOD", TRI, False, (2).to_bytes(4, "little")),   # TRI_MODULE
    ("CONFIG_MOD", CHAR, False, b"m"),
    ("CONFIG_NAME", ("char_arr", 4, False), False, b"bpf\x00"),  # truncated
    ("CONFIG_PREEMPT_RT", BOOL, True, b"\x00"),   # unset + __weak -> zero
    ("LINUX_KERNEL_VERSION", ("int", 4, False), False,
     ((7 << 16) + (2 << 8)).to_bytes(4, "little")),
    ("LINUX_HAS_SYSCALL_WRAPPER", BOOL, True, b"\x01"),
    ("LINUX_HAS_BPF_COOKIE", BOOL, True, b"\x01"),
    ("LINUX_SOMETHING_NEW", INT, True, bytes(4)),  # weak unknown virtual
])
def test_values_match_libbpf(name, decl, weak, want):
    assert KC.value(name, decl, weak) == want


@pytest.mark.parametrize("name,decl,weak", [
    ("CONFIG_PREEMPT_RT", BOOL, False),   # unset and not __weak: load fails
    ("CONFIG_MOD", BOOL, False),          # 'm' into a bool
    ("CONFIG_HZ", BOOL, False),           # a number into a bool
    ("CONFIG_HZ", U8, False),             # 1000 doesn't fit a byte
    ("CONFIG_HZ", I8, False),
    ("CONFIG_NAME", INT, False),          # a string into an int
    ("CONFIG_HZ", ("unknown", 16, False), False),
    ("LINUX_SOMETHING_NEW", INT, False),  # unknown virtual, not weak
    ("NOT_A_CONFIG", INT, True),          # neither CONFIG_ nor LINUX_
])
def test_what_libbpf_rejects_is_an_error(name, decl, weak):
    with pytest.raises(KconfigError):
        KC.value(name, decl, weak)


def test_kernel_version_from_the_makefile():
    mk = "VERSION = 7\nPATCHLEVEL = 2\nSUBLEVEL = 300\nEXTRAVERSION = -rc1\n"
    assert kconfig.makefile_version(mk) == (7 << 16) + (2 << 8) + 255


# --- the executor -----------------------------------------------------------

def load_hz():
    """r1 = &CONFIG_HZ; r0 = *(u32 *)r1; return r0 == 1000 ? 1 : 2"""
    return asm.prog(asm.ld_imm64(R1, 0), asm.ldx(4, R0, R1, 0),
                    asm.jeq_imm(R0, 1000, 2),
                    asm.mov64_imm(R0, 2), asm.exit_(),
                    asm.mov64_imm(R0, 1), asm.exit_())


def returns(n):
    return asm.prog(asm.mov64_imm(R0, n), asm.exit_())


HZ = {"CONFIG_HZ": (INT, False)}
C_SIDE = dict(kconfig_vars=HZ, relocs={0: "CONFIG_HZ"}, kconfig=KC)


def test_a_translation_hardcoding_the_config_value_is_equiv():
    verdict, _ = compare(load_hz(), returns(1), b_kw={}, **C_SIDE)
    assert verdict == "EQUIV"


def test_hardcoding_the_wrong_value_is_inequiv():
    verdict, _ = compare(load_hz(), returns(2), b_kw={}, **C_SIDE)
    assert verdict == "INEQUIV"


def test_without_a_config_the_extern_still_bails():
    with pytest.raises(Bail, match="__kconfig extern CONFIG_HZ"):
        compare(load_hz(), returns(1), b_kw={}, **dict(C_SIDE, kconfig=None))


def test_a_value_libbpf_would_refuse_bails():
    # 1000 into a bool: the C object would not load
    bad = {"CONFIG_HZ": (BOOL, False)}
    with pytest.raises(Bail, match="CONFIG_HZ"):
        compare(load_hz(), returns(1), b_kw={}, **dict(C_SIDE, kconfig_vars=bad))


def test_the_extern_is_read_only():
    store = asm.prog(asm.ld_imm64(R1, 0), asm.st_imm(4, R1, 0, 5),
                     asm.mov64_imm(R0, 0), asm.exit_())
    with pytest.raises(Bail, match="read-only region kcfg:"):
        compare(store, store, **C_SIDE)
