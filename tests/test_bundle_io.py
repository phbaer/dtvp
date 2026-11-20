"""The shared ZIP container helpers."""

import io
import os
import struct
import zipfile

import pytest

from dtvp.bundle_io import (
    BundleError,
    ZipBundleReader,
    ZipBundleWriter,
    assert_safe_member_name,
    atomic_output,
    jsonl_line,
    sha256_hex,
    stable_json_bytes,
)

LIMITS = {
    "max_members": 10,
    "max_total_uncompressed": 10_000,
    "max_line_bytes": 100,
}


def _zip(path, members):
    with open(path, "wb") as handle, ZipBundleWriter(handle) as bundle:
        for name, data in members.items():
            bundle.write_member(name, data)
    return path


def _raw_zip(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_encodings_are_stable():
    assert stable_json_bytes({"b": 1, "a": "ü"}) == b'{\n  "a": "\xc3\xbc",\n  "b": 1\n}\n'
    assert jsonl_line({"b": [1, 2], "a": None}) == b'{"a":null,"b":[1,2]}\n'
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


@pytest.mark.parametrize("name", ["", "/abs", "\\win", "a/../b", "./a", "a//b", "..", "a/"])
def test_unsafe_names_are_refused(name):
    with pytest.raises(BundleError) as raised:
        assert_safe_member_name(name)
    assert raised.value.code == "C1"
    with pytest.raises(KeyError):
        assert_safe_member_name(name, KeyError)


def test_writer_members_are_byte_identical_for_the_same_input(tmp_path):
    members = {"records/a/a-0001.jsonl": jsonl_line({"x": 1}) * 50, "config/x.json": b"{}"}
    first = _zip(tmp_path / "one.zip", members)
    second = _zip(tmp_path / "two.zip", members)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        for info in archive.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.external_attr >> 16 == 0o600
            assert info.compress_type == zipfile.ZIP_DEFLATED


def test_writer_counts_digest_bytes_and_lines(tmp_path):
    data = jsonl_line({"a": 1}) + jsonl_line({"b": 2})
    with open(tmp_path / "x.zip", "wb") as handle, ZipBundleWriter(handle) as bundle:
        with bundle.member("records/x.jsonl") as member:
            for line in data.splitlines(keepends=True):
                member.write(line)
    stats = bundle.members[0]
    assert (stats.name, stats.sha256, stats.bytes, stats.lines) == (
        "records/x.jsonl",
        sha256_hex(data),
        len(data),
        2,
    )


class _Unseekable(io.RawIOBase):
    def __init__(self):
        self.buffer = bytearray()

    def writable(self):
        return True

    def write(self, data):
        self.buffer.extend(data)
        return len(data)

    def seekable(self):
        return False

    def tell(self):
        raise OSError("unseekable")


def test_writer_works_on_an_unseekable_stream(tmp_path):
    sink = _Unseekable()
    with ZipBundleWriter(sink) as bundle:
        bundle.write_member("a.jsonl", b'{"a":1}\n' * 100)
    path = tmp_path / "piped.zip"
    path.write_bytes(bytes(sink.buffer))
    with ZipBundleReader(str(path), **LIMITS) as reader:
        assert list(reader.iter_lines("a.jsonl")) == [b'{"a":1}\n'] * 100


def test_reader_refuses_too_many_members(tmp_path):
    path = _zip(tmp_path / "x.zip", {f"m{index}": b"" for index in range(11)})
    with pytest.raises(BundleError) as raised:
        ZipBundleReader(str(path), **LIMITS)
    assert raised.value.code == "C4"


def test_reader_refuses_a_declared_total_over_the_limit(tmp_path):
    path = _zip(tmp_path / "x.zip", {"a": b"x" * 6000, "b": b"y" * 6000})
    with pytest.raises(BundleError) as raised:
        ZipBundleReader(str(path), **LIMITS)
    assert raised.value.code == "C5"


def test_reader_refuses_a_ratio_over_the_limit_only_when_set(tmp_path):
    path = _zip(tmp_path / "x.zip", {"a": b"\0" * 9000})
    with ZipBundleReader(str(path), **LIMITS):
        pass
    with pytest.raises(BundleError, match="expands"):
        ZipBundleReader(str(path), max_ratio=10, **LIMITS)


def test_reader_refuses_an_unsafe_name(tmp_path):
    path = _raw_zip(tmp_path / "x.zip", {"a/../../etc": b"x"})
    with pytest.raises(BundleError) as raised:
        ZipBundleReader(str(path), **LIMITS)
    assert raised.value.code == "C1"


def _shrink_declared_size(path, name, new_size):
    """Rewrite the declared uncompressed size of a member in both headers."""
    data = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(name)
    # Local file header: uncompressed size at offset 22.
    struct.pack_into("<I", data, info.header_offset + 22, new_size)
    central = data.rfind(b"PK\x01\x02")
    while central >= 0:
        name_length = struct.unpack_from("<H", data, central + 28)[0]
        if data[central + 46 : central + 46 + name_length] == name.encode():
            struct.pack_into("<I", data, central + 24, new_size)
            break
        central = data.rfind(b"PK\x01\x02", 0, central)
    path.write_bytes(bytes(data))


def test_reader_refuses_a_member_larger_than_declared(tmp_path):
    path = _raw_zip(tmp_path / "x.zip", {"a.jsonl": b'{"a":1}\n' * 20})
    _shrink_declared_size(path, "a.jsonl", 16)
    with ZipBundleReader(str(path), **LIMITS) as reader:
        assert reader.declared_size("a.jsonl") == 16
        with pytest.raises(BundleError) as raised:
            list(reader.iter_lines("a.jsonl"))
        assert raised.value.code == "C10"
        with pytest.raises(BundleError):
            reader.read_bytes("a.jsonl")


def test_reader_refuses_a_bad_crc(tmp_path):
    path = tmp_path / "x.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("a.jsonl", b'{"a":1}\n' * 5)
    data = bytearray(path.read_bytes())
    position = data.find(b'{"a":1}')
    data[position + 1] = ord("b")
    path.write_bytes(bytes(data))
    with ZipBundleReader(str(path), **LIMITS) as reader:
        with pytest.raises(BundleError, match="CRC") as raised:
            list(reader.iter_lines("a.jsonl"))
        assert raised.value.code == "C10"


def test_reader_refuses_a_truncated_stream(tmp_path):
    path = _zip(tmp_path / "x.zip", {"a.jsonl": os.urandom(4000)})
    path.write_bytes(path.read_bytes()[:-200])
    with pytest.raises(BundleError) as raised:
        with ZipBundleReader(str(path), **LIMITS) as reader:
            reader.read_bytes("a.jsonl")
    assert raised.value.code == "C10"
    path.write_bytes(b"not a zip")
    with pytest.raises(BundleError):
        ZipBundleReader(str(path), **LIMITS)


def test_reader_refuses_a_line_over_the_maximum(tmp_path):
    path = _zip(tmp_path / "x.zip", {"a.jsonl": b"x" * 100 + b"\n" + b"y" * 101 + b"\n"})
    with ZipBundleReader(str(path), **LIMITS) as reader:
        lines = reader.iter_lines("a.jsonl")
        assert next(lines) == b"x" * 100 + b"\n"
        with pytest.raises(BundleError) as raised:
            next(lines)
    assert raised.value.code == "C9"


def test_reader_reads_lines_and_bytes(tmp_path):
    path = _zip(tmp_path / "x.zip", {"a.jsonl": b"1\n2\n3", "b": b"bytes"})
    with ZipBundleReader(str(path), **LIMITS) as reader:
        assert reader.names() == ["a.jsonl", "b"]
        assert "b" in reader
        assert list(reader.iter_lines("a.jsonl")) == [b"1\n", b"2\n", b"3"]
        assert reader.read_bytes("b") == b"bytes"
        with pytest.raises(KeyError):
            reader.read_bytes("missing")


def test_atomic_output_failure_leaves_no_temp_file_and_no_target(tmp_path):
    target = tmp_path / "out" / "dump.zip"
    with pytest.raises(RuntimeError):
        with atomic_output(str(target)) as handle:
            handle.write(b"partial")
            raise RuntimeError("interrupted")
    assert not target.exists()
    assert list(target.parent.iterdir()) == []


def test_atomic_output_replace_failure_keeps_the_old_target(tmp_path, monkeypatch):
    (tmp_path / "out").mkdir()
    target = tmp_path / "out" / "dump.zip"
    target.write_bytes(b"old")

    def broken_replace(*_args):
        raise OSError("no")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError):
        with atomic_output(str(target)) as handle:
            handle.write(b"new")
    assert target.read_bytes() == b"old"
    assert [path.name for path in target.parent.iterdir()] == ["dump.zip"]


def test_atomic_output_applies_the_mode(tmp_path):
    target = tmp_path / "dump.zip"
    with atomic_output(str(target), mode=0o640) as handle:
        handle.write(b"data")
    assert target.read_bytes() == b"data"
    assert target.stat().st_mode & 0o777 == 0o640
