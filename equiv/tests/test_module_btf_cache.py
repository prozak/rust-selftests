"""Module BTF is a proof input, including module identity and distilled bases."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bpfelf
import guard


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(guard, 'HERE', str(tmp_path))
    monkeypatch.setattr(guard, 'REPO', str(tmp_path))
    monkeypatch.setattr(guard, 'DEFAULT_C_DIR', str(tmp_path))
    monkeypatch.setattr(guard, 'TOOL_FILES', ['check.py'])
    (tmp_path / 'check.py').write_text('checker')

    class Elf:
        def __init__(self, path):
            self.sections = json.loads(Path(path).read_text())

        def section_by_name(self, name):
            return SimpleNamespace(data=self.sections[name].encode()) if name in self.sections else None

    monkeypatch.setattr(bpfelf, 'BpfElf', Elf)


def test_module_add_remove_rename_and_btf_changes_invalidate_cache(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    empty = guard.tool_hash()
    module = tmp_path / 'test.ko'
    module.write_text(json.dumps({'.BTF': 'old'}))
    original = guard.tool_hash()
    assert original != empty
    module.write_text(json.dumps({'.BTF': 'new'}))
    updated = guard.tool_hash()
    assert updated != original
    module.write_text(json.dumps({'.BTF': 'new', '.BTF.base': 'base'}))
    base = guard.tool_hash()
    assert base != updated
    renamed = module.rename(tmp_path / 'renamed.ko')
    assert guard.tool_hash() != base
    renamed.unlink()
    assert guard.tool_hash() == empty


def test_unrelated_module_sections_do_not_invalidate_btf_proofs(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    module = tmp_path / 'test.ko'
    module.write_text(json.dumps({'.BTF': 'types', '.debug_info': 'old'}))
    original = guard.tool_hash()
    module.write_text(json.dumps({'.BTF': 'types', '.debug_info': 'new'}))
    assert guard.tool_hash() == original
