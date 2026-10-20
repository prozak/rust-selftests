"""`// BTF_FWD: S` turns rustc's memberless STRUCT/UNION into a BTF FWD in place."""
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from btf_rename import main, elf_find_section
from bpfelf import BpfElf
from test_test_tags import synth_object


def install_btf(obj, types, strings):
    buf = bytearray(obj.read_bytes())
    sh, _, _, _ = elf_find_section(buf, ".BTF")
    btf = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types),
                      len(types), len(strings)) + types + strings
    off = len(buf)
    buf.extend(btf)
    struct.pack_into("<QQ", buf, sh + 24, off, len(btf))
    obj.write_bytes(buf)
    return bytes(buf)


@pytest.mark.parametrize("kind", [4, 5])
def test_fwd_rewrites_only_the_named_memberless_type(tmp_path, kind):
    obj = tmp_path / "fwd.bpf.o"
    synth_object(obj)
    strings = b"\0S\0T\0x\0int\0"
    types = struct.pack("<III", 1, kind << 24, 0)  # [1] memberless 'S'
    types += struct.pack("<IIII", 7, 1 << 24, 4, 1 << 24 | 32)  # [2] INT int
    types += struct.pack("<III", 3, kind << 24 | 1, 4)  # [3] 'T' with a member
    types += struct.pack("<III", 5, 2, 0)  #     member x: int at 0
    types += struct.pack("<III", 0, 2 << 24, 1)  # [4] PTR -> S
    install_btf(obj, types, strings)
    before = BpfElf(obj)
    source = tmp_path / "fwd.rs"
    source.write_text("// BTF_FWD: S\n")
    main(obj, source=source)
    after = BpfElf(obj)
    expected = before.btf_types().copy()
    expected[1] = (7, "S", 0, 0, None)
    assert after.btf_types() == expected
    # kind_flag (bit 31) marks a union FWD; the struct/union payload stays 0
    sh, off, _, _ = elf_find_section(bytearray(obj.read_bytes()), ".BTF")
    data = obj.read_bytes()[off:]
    _, info, payload = struct.unpack_from("<III", data, 24)
    assert info >> 31 == (kind == 5)
    assert payload == 0


def test_fwd_needs_a_memberless_type_and_writes_nothing_otherwise(tmp_path):
    obj = tmp_path / "no-fwd.bpf.o"
    synth_object(obj)
    strings = b"\0S\0x\0int\0"
    types = struct.pack("<IIII", 5, 1 << 24, 4, 1 << 24 | 32)  # [1] INT int
    types += struct.pack("<III", 1, 4 << 24 | 1, 4)  # [2] 'S' with a member
    types += struct.pack("<III", 3, 1, 0)
    before = install_btf(obj, types, strings)
    source = tmp_path / "fwd.rs"
    source.write_text("// BTF_FWD: S\n")
    with pytest.raises(ValueError, match="memberless"):
        main(obj, source=source)
    assert obj.read_bytes() == before
