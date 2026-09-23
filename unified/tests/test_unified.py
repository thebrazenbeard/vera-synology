import json,py_compile,subprocess,unittest
from pathlib import Path
U=Path(__file__).resolve().parents[1]
class T(unittest.TestCase):
 def test_bindings(self):
  b=json.loads((U/"component-bindings.json").read_text());self.assertEqual("159c9301d1d0b89e3fc2c03215690ba71ff45634",b["dsmctl"]["commit"])
 def test_sources(self):
  [py_compile.compile(str(U/p),doraise=True) for p in ("payload/bin/veramesh_supervisor.py","payload/bin/veramesh_runtime_init.py","tools/build_unified_spk.py","tools/verify_unified_spk.py","payload/bin/adopt-standalone-verarelay.py")]
 def test_relay_launcher_is_source_bound(self):
  s=(U/"payload/bin/run-verarelay.sh").read_text()
  self.assertIn("src/runtime.js",s)
  self.assertIn("VERA_RELAY_VAR=/var/packages/VeraMesh/var/relay",s)
  self.assertNotIn("/var/packages/VeraRelay/var",s)
 def test_adoption_guardrails(self):
  s=(U/"payload/bin/adopt-standalone-verarelay.py").read_text()
  self.assertIn("/var/packages/VeraRelay/var",s)
  self.assertIn("source-manifest.json",s)
  self.assertIn("state copy verification failed",s)
  self.assertIn("safe_to_uninstall_standalone_after_review",s)
  self.assertIn("enable(False)",s)
  self.assertIn("resolve_state_root(OLDVAR,True)",s)
  self.assertIn("owner=package_owner()",s)
  self.assertIn("if unified_changed:",s)
 def test_synology_root_symlink_resolution(self):
  import importlib.util,tempfile
  spec=importlib.util.spec_from_file_location("adopter",U/"payload/bin/adopt-standalone-verarelay.py")
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);real=base/"real";real.mkdir();(real/"state").mkdir();(real/"state"/"x").write_text("ok")
   link=base/"var";link.symlink_to(real,target_is_directory=True)
   self.assertEqual(real.resolve(),m.resolve_state_root(link,True))
   entries,digest,files,bytes_=m.manifest(real)
   self.assertEqual(1,files);self.assertTrue(digest);self.assertGreaterEqual(len(entries),2)
   (real/"bad").symlink_to(base/"elsewhere")
   with self.assertRaises(m.E):m.manifest(real)
 def test_fresh_install_bootstrap_uses_real_synology_status(self):
  s=(U/"spk/scripts/postinst").read_text()
  self.assertIn('STATUS="${SYNOPKG_PKG_STATUS:-INSTALL}"',s)
  self.assertIn('postinstall "$STATUS"',s)
  self.assertIn('veramesh_state.py" initialize',s)
  self.assertIn('veramesh_runtime_init.py',s)
  self.assertIn('"$STATUS"',s)
 def test_persistent_module_config_reinstall_recovery(self):
  import importlib.util,os,tempfile
  spec=importlib.util.spec_from_file_location("runtime_init",U/"payload/bin/veramesh_runtime_init.py")
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as td:
   var=Path(td);runtime=var/"runtime";runtime.mkdir()
   config=runtime/"modules.json"
   config.write_text('{"schema":"poison"}\n');os.chmod(config,0)
   old_inode=config.lstat().st_ino
   recovery=m.initialize(var,"INSTALL")
   self.assertEqual(m.RECOVERY_SCHEMA,recovery["schema"])
   self.assertEqual(old_inode,recovery["source_inode"])
   self.assertEqual(m.DEFAULT,json.loads(config.read_text()))
   quarantined=Path(recovery["quarantine"])
   self.assertTrue(quarantined.is_file())
   self.assertEqual(0,quarantined.stat().st_mode & 0o777)
 def test_upgrade_does_not_reset_invalid_module_config(self):
  import importlib.util,tempfile
  spec=importlib.util.spec_from_file_location("runtime_init_upgrade",U/"payload/bin/veramesh_runtime_init.py")
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as td:
   var=Path(td);runtime=var/"runtime";runtime.mkdir()
   config=runtime/"modules.json";config.write_text('{"schema":"poison"}\n')
   with self.assertRaises(ValueError):m.initialize(var,"UPGRADE")
   self.assertEqual('{"schema":"poison"}\n',config.read_text())
 def test_synology_user_unit_matches_last_runtime_proven_shape(self):
  unit=(U/"spk/conf/systemd/pkguser-veramesh.service").read_text()
  self.assertIn("After=network.target",unit)
  info=(U/"spk/INFO").read_text()
  self.assertNotIn("start_dep_services=",info)
 def test_shell(self):
  [subprocess.run(["sh","-n",str(U/p)],check=True) for p in ("payload/bin/run-veramesh-gateway.sh","payload/bin/run-verarelay.sh","spk/scripts/postinst","spk/scripts/postupgrade")]
if __name__=="__main__":unittest.main()
