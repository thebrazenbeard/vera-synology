import importlib.util, json, py_compile, subprocess, tempfile, unittest
from pathlib import Path
U=Path(__file__).resolve().parents[1]

class WorkBridgePackageTests(unittest.TestCase):
 def test_bindings(self):
  b=json.loads((U/"component-bindings.json").read_text())
  self.assertEqual("0.2.0-0009",b["package"]["version"])
  self.assertEqual("c063b9fbf96cfaf693e2dfd050a644de16be3a3b",b["vera_mesh"]["commit"])
  self.assertEqual("8e0e9831adc2a6a8d41145c71c8bd64d9a489c77",b["workbridge_mcp"]["commit"])
 def test_configurator_compiles_and_read_write_profiles(self):
  p=U/"payload/bin/configure-workbridge.py";py_compile.compile(str(p),doraise=True)
  spec=importlib.util.spec_from_file_location("wb_cfg",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as td:
   roots=m.normalize_roots([td])
   read,_=m.configs(roots,"read");write,_=m.configs(roots,"write")
   self.assertEqual([],read["write_roots"]);self.assertFalse(read["process"]["enabled"])
   self.assertEqual(roots,write["write_roots"]);self.assertFalse(write["process"]["enabled"])
 def test_gateway_launcher_contract(self):
  s=(U/"payload/bin/run-veramesh-gateway.sh").read_text()
  self.assertIn("127.0.0.1:17447",s);self.assertIn("-workbridge-config",s);self.assertIn("VERAMESH_WORKBRIDGE_TOKEN",s)
  self.assertIn('exec "$B" -listen 127.0.0.1:17446',s)
  subprocess.run(["sh","-n",str(U/"payload/bin/run-veramesh-gateway.sh")],check=True)
 def test_runtime_init_preserves_existing_module_schema(self):
  s=(U/"payload/bin/veramesh_runtime_init.py").read_text()
  self.assertIn('{"edge":{"enabled":True},"gateway":{"enabled":False},"relay":{"enabled":False}}',s)
  self.assertIn('var/"workbridge"',s)

if __name__=="__main__":unittest.main()
