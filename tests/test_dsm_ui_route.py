from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DsmUiRouteTests(unittest.TestCase):
    def test_package_center_open_targets_webman_thirdparty_route(self):
        cfg = json.loads((ROOT / "payload" / "ui" / "config").read_text(encoding="utf-8"))
        app = cfg[".url"]["com.vera.MeshEdge"]
        self.assertEqual("/webman/3rdparty/VeraMesh/index.html", app["url"])
        self.assertTrue((ROOT / "payload" / "ui" / "index.html").is_file())

    def test_repair_version_is_0017(self):
        info = (ROOT / "spk" / "INFO").read_text(encoding="utf-8")
        self.assertIn('version="0.1.0-0017"', info)

if __name__ == "__main__":
    unittest.main()
