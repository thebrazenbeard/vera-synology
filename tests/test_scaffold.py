from __future__ import annotations

import hashlib
import gzip
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


build_spk = load_module("build_spk", ROOT / "tools" / "build_spk.py")
verify_spk = load_module("verify_spk", ROOT / "tools" / "verify_spk.py")
state_mod = load_module("veramesh_state", ROOT / "payload" / "bin" / "veramesh_state.py")
sys.modules["veramesh_state"] = state_mod
lifecycle_mod = load_module("veramesh_lifecycle", ROOT / "payload" / "bin" / "veramesh_lifecycle.py")
sys.modules["veramesh_lifecycle"] = lifecycle_mod
scaffold_mod = load_module("veramesh_edge_contract", ROOT / "payload" / "bin" / "veramesh_edge.py")


class SourceContractTests(unittest.TestCase):
    def test_required_source_paths_exist(self):
        required = [
            'README.md','tools/build_spk.py','tools/verify_spk.py','spk/INFO',
            'spk/conf/privilege','spk/conf/resource','spk/conf/PKG_DEPS',
            'spk/conf/systemd/pkguser-veramesh.service','spk/scripts/preinst',
            'spk/scripts/postinst','spk/scripts/preuninst','spk/scripts/postuninst',
            'spk/scripts/preupgrade','spk/scripts/postupgrade','spk/scripts/start-stop-status',
            'payload/bin/veramesh_state.py','payload/bin/veramesh_edge.py',
            'payload/bin/veramesh_lifecycle.py','payload/ui/config','payload/ui/index.html',
            'docs/TOOLKIT_QUALIFICATION.md',
        ]
        missing = [p for p in required if not (ROOT / p).is_file()]
        self.assertEqual([], missing, f'missing required source paths: {missing}')

    def test_info_has_required_dsm7_fields_and_scaffold_identity(self):
        info = (ROOT / 'spk/INFO').read_text()
        for token in [
            'package="VeraMesh"','version="0.1.0-0016"','os_min_ver="7.2-72806"',
            'description=','arch="armada38x"','maintainer=','dsmuidir="ui"',
            'dsmappname="com.vera.MeshEdge"','precheckstartstop="yes"',
        ]:
            self.assertIn(token, info)

    def test_privilege_is_package_user_and_resource_surface_is_narrow(self):
        privilege = json.loads((ROOT / 'spk/conf/privilege').read_text())
        resource = json.loads((ROOT / 'spk/conf/resource').read_text())
        self.assertEqual('package', privilege['defaults']['run-as'])
        self.assertEqual({'systemd-user-unit'}, set(resource))

    def test_dependency_surface_is_python311_only(self):
        deps = (ROOT / 'spk/conf/PKG_DEPS').read_text()
        self.assertIn('[python311]', deps)
        self.assertNotIn('node', deps.lower())
        self.assertNotIn('webstation', deps.lower())
        self.assertNotIn('php', deps.lower())

    def test_ui_is_admin_default_and_explicit_about_edge_scope(self):
        config = json.loads((ROOT / 'payload/ui/config').read_text())
        app = config['.url']['com.vera.MeshEdge']
        self.assertNotIn('allUsers', app)
        html = (ROOT / 'payload/ui/index.html').read_text()
        self.assertIn('LIVE_EDGE_PROXY_READY_DURABLE_RELAY_NOT_IMPLEMENTED', html)
        self.assertIn('Durable relay', html)

    def test_edge_service_is_loopback_transparent_and_has_no_subprocess_surface(self):
        source = (ROOT / 'payload/bin/veramesh_edge.py').read_text()
        self.assertIn('socket.AF_UNIX', source)
        self.assertIn('socket.AF_INET', source)
        self.assertIn('127.0.0.1', source)
        self.assertNotIn('subprocess', source)
        self.assertIn('UNSUPPORTED_OPERATION', source)
        self.assertIn('durable_relay_implemented', source)

    def test_shell_scripts_parse_and_do_not_generate_identity(self):
        for script in sorted((ROOT / 'spk/scripts').iterdir()):
            subprocess.run(['sh','-n',str(script)], check=True)
            text = script.read_text().lower()
            self.assertNotIn('openssl gen', text)
            self.assertNotIn('ssh-keygen', text)
            self.assertNotIn('curl ', text)
            self.assertNotIn('wget ', text)

    def test_outer_icon_dimensions_are_exact(self):
        for rel, expected in [('spk/PACKAGE_ICON.PNG',64),('spk/PACKAGE_ICON_256.PNG',256)]:
            data = (ROOT / rel).read_bytes()
            self.assertEqual(b'\x89PNG\r\n\x1a\n', data[:8])
            width, height = struct.unpack('>II', data[16:24])
            self.assertEqual((expected, expected), (width,height))


class StateTests(unittest.TestCase):
    def test_initialize_is_idempotent_for_exact_valid_existing_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'state' / 'scaffold-state.json'
            first = state_mod.initialize(path)
            before = path.read_bytes()
            second = state_mod.initialize(path)
            self.assertEqual(first, second)
            self.assertEqual(before, path.read_bytes())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_initialize_refuses_invalid_existing_state_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'state' / 'scaffold-state.json'
            path.parent.mkdir(mode=0o700)
            path.write_text('{"schema":"wrong"}\n')
            os.chmod(path, 0o600)
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                state_mod.initialize(path)
            self.assertEqual(before, path.read_bytes())

    def test_initialize_rejects_symlink_state_parent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real_parent = base / "real"
            real_parent.mkdir(mode=0o700)
            link_parent = base / "linked"
            link_parent.symlink_to(real_parent, target_is_directory=True)
            path = link_parent / "scaffold-state.json"
            with self.assertRaisesRegex(ValueError, "parent"):
                state_mod.initialize(path)
            self.assertFalse((real_parent / "scaffold-state.json").exists())

    def test_verify_rejects_mutated_edge_semantic_claims(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'state.json'
            bad = dict(state_mod.DEFAULT_STATE)
            bad['durable_relay_implemented'] = True
            path.write_text(json.dumps(bad))
            os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                state_mod.verify(path)


class ControlSocketTests(unittest.TestCase):
    def test_control_socket_rejects_symlink_run_directory(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real_run = base / "real-run"
            real_run.mkdir(mode=0o700)
            link_run = base / "run"
            link_run.symlink_to(real_run, target_is_directory=True)
            old_run, old_socket = scaffold_mod.RUN_DIR, scaffold_mod.CONTROL_SOCKET
            scaffold_mod.RUN_DIR = link_run
            scaffold_mod.CONTROL_SOCKET = link_run / "control.sock"
            try:
                with self.assertRaisesRegex(RuntimeError, "run directory"):
                    scaffold_mod._prepare_control_socket()
            finally:
                scaffold_mod.RUN_DIR, scaffold_mod.CONTROL_SOCKET = old_run, old_socket


class BuildAndVerifyTests(unittest.TestCase):
    def test_build_is_byte_deterministic(self):
        a = build_spk.build_spk_bytes()
        b = build_spk.build_spk_bytes()
        self.assertEqual(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        self.assertEqual(a, b)

    def test_build_excludes_python_bytecode_and_pycache(self):
        junk_dir = ROOT / "payload" / "bin" / "__pycache__"
        junk = junk_dir / "injected.cpython-311.pyc"
        junk_dir.mkdir(parents=True, exist_ok=True)
        junk.write_bytes(b"not-source")
        try:
            package_tgz = build_spk.build_package_tgz()
            with tarfile.open(fileobj=io.BytesIO(package_tgz), mode="r:gz") as tf:
                names = [m.name for m in tf.getmembers()]
            self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names), names)
        finally:
            junk.unlink(missing_ok=True)

    def test_built_spk_passes_structural_verifier(self):
        result = verify_spk.verify_bytes(build_spk.build_spk_bytes())
        self.assertGreaterEqual(result['outer_members'], 15)
        self.assertGreaterEqual(result['payload_members'], 12)

    def test_built_archive_has_no_duplicate_members_and_scripts_are_executable(self):
        spk = build_spk.build_spk_bytes()
        with tarfile.open(fileobj=io.BytesIO(spk), mode='r:') as tf:
            members = tf.getmembers()
            names = [m.name for m in members]
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(names, sorted(names))
            for m in members:
                if m.name.startswith('scripts/'):
                    self.assertEqual(0o755, m.mode)

    def test_verifier_rejects_duplicate_outer_member(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as tf:
            for _ in range(2):
                ti = tarfile.TarInfo('INFO'); data=b'x'; ti.size=1; tf.addfile(ti, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify_spk.verify_bytes(raw.getvalue())

    def test_verifier_rejects_bytecode_payload_members(self):
        package_raw = io.BytesIO()
        with gzip.GzipFile(fileobj=package_raw, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
                for name, data in sorted({
                    "bin/veramesh_state.py": b"x",
                    "bin/veramesh_edge.py": b"x",
                    "bin/__pycache__/junk.pyc": b"x",
                    "ui/config": b"{}",
                    "ui/index.html": b"x",
                }.items()):
                    ti=tarfile.TarInfo(name); ti.size=len(data)
                    ti.mode=0o755 if name.startswith('bin/') else 0o644
                    ti.mtime=0; ti.uid=0; ti.gid=0; ti.uname=''; ti.gname=''
                    tf.addfile(ti, io.BytesIO(data))
        spk_raw = io.BytesIO()
        outer_files = {
            "INFO": b'package="VeraMesh"\nversion="0.1.0-0016"\nos_min_ver="7.2-72806"\narch="armada38x"\ndsmuidir="ui"\ndsmappname="com.vera.MeshEdge"\n',
            "package.tgz": package_raw.getvalue(),
            "conf/PKG_DEPS": b"[python311]\n",
            "conf/privilege": b'{"defaults":{"run-as":"package"}}',
            "conf/resource": b'{"systemd-user-unit":{}}',
            "conf/systemd/pkguser-veramesh.service": b"x",
            "scripts/preinst": b"x", "scripts/postinst": b"x",
            "scripts/preuninst": b"x", "scripts/postuninst": b"x",
            "scripts/preupgrade": b"x", "scripts/postupgrade": b"x",
            "scripts/start-stop-status": b"x",
            "PACKAGE_ICON.PNG": b"x", "PACKAGE_ICON_256.PNG": b"x",
        }
        with tarfile.open(fileobj=spk_raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name, data in sorted(outer_files.items()):
                ti=tarfile.TarInfo(name); ti.size=len(data)
                ti.mode=0o755 if name.startswith('scripts/') else 0o644
                ti.mtime=0; ti.uid=0; ti.gid=0; ti.uname=''; ti.gname=''
                tf.addfile(ti, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "bytecode"):
            verify_spk.verify_bytes(spk_raw.getvalue())

    def test_source_manifest_is_reproducible_and_matches_source_tree(self):
        tool = ROOT / 'tools/make_source_manifest.py'
        manifest = ROOT / 'SOURCE_MANIFEST.json'
        self.assertTrue(tool.is_file())
        self.assertTrue(manifest.is_file())
        subprocess.run(['python', str(tool)], cwd=ROOT, check=True)
        first = manifest.read_bytes()
        subprocess.run(['python', str(tool)], cwd=ROOT, check=True)
        self.assertEqual(first, manifest.read_bytes())
        entries = json.loads(first)
        self.assertNotIn('SOURCE_MANIFEST.json', {e['path'] for e in entries})
        for entry in entries:
            data = (ROOT / entry['path']).read_bytes()
            self.assertEqual(len(data), entry['bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])

    def test_qualification_doc_keeps_device_effects_open(self):
        doc = (ROOT / 'docs/TOOLKIT_QUALIFICATION.md').read_text()
        self.assertIn('DS216 V16 live-edge qualification boundary', doc)
        self.assertIn('Durable relay remains explicitly NOT_IMPLEMENTED', doc)


if __name__ == '__main__':
    unittest.main()
