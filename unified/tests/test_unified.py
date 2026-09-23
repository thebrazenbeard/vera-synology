import json,py_compile,subprocess,unittest
from pathlib import Path
U=Path(__file__).resolve().parents[1]
class T(unittest.TestCase):
 def test_bindings(self):
  b=json.loads((U/"component-bindings.json").read_text());self.assertEqual("159c9301d1d0b89e3fc2c03215690ba71ff45634",b["dsmctl"]["commit"])
 def test_sources(self):
  [py_compile.compile(str(U/p),doraise=True) for p in ("payload/bin/veramesh_supervisor.py","payload/bin/veramesh_runtime_init.py","tools/build_unified_spk.py","tools/verify_unified_spk.py")]
 def test_shell(self):
  [subprocess.run(["sh","-n",str(U/p)],check=True) for p in ("payload/bin/run-veramesh-gateway.sh","payload/bin/run-verarelay.sh","spk/scripts/postinst","spk/scripts/postupgrade")]
if __name__=="__main__":unittest.main()
