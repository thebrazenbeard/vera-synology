from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


build_spk = load_module("build_spk_info", ROOT / "tools" / "build_spk.py")
verify_spk = load_module("verify_spk_info", ROOT / "tools" / "verify_spk.py")


def replace_info(info_bytes: bytes) -> bytes:
    original = build_spk.build_spk_bytes()
    files: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as tf:
        for member in tf.getmembers():
            data = info_bytes if member.name == "INFO" else tf.extractfile(member).read()
            copy = tarfile.TarInfo(member.name)
            copy.size = len(data)
            copy.mode = member.mode
            copy.mtime = member.mtime
            copy.uid = member.uid
            copy.gid = member.gid
            copy.uname = member.uname
            copy.gname = member.gname
            files.append((copy, data))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member, data in files:
            tf.addfile(member, io.BytesIO(data))
    return raw.getvalue()


class InfoContractTests(unittest.TestCase):
    def _valid_info(self) -> bytes:
        return (ROOT / "spk" / "INFO").read_bytes()

    def test_current_info_parses_to_exact_closed_map(self):
        parsed = verify_spk._parse_info(self._valid_info())
        self.assertEqual(verify_spk.INFO_EXPECTED, parsed)

    def test_contradictory_duplicate_field_is_rejected(self):
        hostile = self._valid_info() + b'arch="x86_64"\n'
        with self.assertRaisesRegex(ValueError, "duplicate field: arch"):
            verify_spk.verify_bytes(replace_info(hostile))

    def test_identical_duplicate_field_is_rejected(self):
        hostile = self._valid_info() + b'arch="noarch"\n'
        with self.assertRaisesRegex(ValueError, "duplicate field: arch"):
            verify_spk.verify_bytes(replace_info(hostile))

    def test_malformed_quoting_is_rejected(self):
        hostile = self._valid_info().replace(b'arch="noarch"\n', b'arch="noarch\n')
        with self.assertRaisesRegex(ValueError, "malformed assignment"):
            verify_spk.verify_bytes(replace_info(hostile))

    def test_expected_token_inside_comment_text_is_rejected_not_counted(self):
        hostile = self._valid_info().replace(
            b'package="VeraMesh"\n',
            b'# package="VeraMesh"\n',
            1,
        )
        with self.assertRaisesRegex(ValueError, "malformed assignment"):
            verify_spk.verify_bytes(replace_info(hostile))

    def test_unknown_field_is_rejected_by_closed_contract(self):
        hostile = self._valid_info() + b'extra="value"\n'
        with self.assertRaisesRegex(ValueError, "contract mismatch"):
            verify_spk.verify_bytes(replace_info(hostile))


if __name__ == "__main__":
    unittest.main()
