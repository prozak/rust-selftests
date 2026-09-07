"""Staging preserves the recorded module link inputs and publishes atomically."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('refresh_testmod', Path(__file__).resolve().parents[2] / 'scripts/refresh-qemu-testmod-btf.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_recorded_link_is_replayed_into_separate_output():
    command = module.link_command('savedcmd_bpf_testmod.ko := /tools/ld.lld -r -T module.lds -o bpf_testmod.ko bpf_testmod.o bpf_testmod.mod.o .module-common.o\n', Path('/tmp/staged module.ko'))
    assert command == ['/tools/ld.lld', '-r', '-T', 'module.lds', '-o', '/tmp/staged module.ko', 'bpf_testmod.o', 'bpf_testmod.mod.o', '.module-common.o']


@pytest.mark.parametrize('command', ['gcc -o bpf_testmod.ko x.o', 'ld -o other.ko x.o', 'ld -o bpf_testmod.ko -o other.ko x.o'])
def test_invalid_recorded_link_is_rejected(command):
    with pytest.raises(ValueError):
        module.link_command('savedcmd := ' + command, Path('/tmp/new.ko'))


def test_copy_keeps_source_and_replaces_destination(tmp_path):
    source, destination = tmp_path / 'source', tmp_path / 'destination'
    source.write_bytes(b'new')
    destination.write_bytes(b'old')
    module.atomic_copy(source, destination)
    assert source.read_bytes() == destination.read_bytes() == b'new'
    assert not (tmp_path / 'destination.btf-new').exists()
