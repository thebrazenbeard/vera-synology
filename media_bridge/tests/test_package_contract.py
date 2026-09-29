import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEDIA = ROOT / "media_bridge"
MEDIA_ROOT = "/var/packages/WorkBridgeMedia/shares/Media/Library"


class WorkBridgeMediaContractTests(unittest.TestCase):
    def test_media_share_and_workbridge_root_contract(self):
        resource_path = MEDIA / "spk" / "conf" / "resource"
        self.assertTrue(resource_path.is_file(), "standalone media resource contract is missing")

        resource = json.loads(resource_path.read_text(encoding="utf-8"))
        self.assertEqual({}, resource.get("systemd-user-unit"))
        self.assertEqual(
            [{"name": "Media", "permission": {"rw": ["WorkBridgeMedia"]}}],
            resource.get("data-share", {}).get("shares"),
        )

        config_path = MEDIA / "payload" / "etc" / "workbridge-media.json"
        self.assertTrue(config_path.is_file(), "bounded WorkBridge media config is missing")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual("WORKBRIDGE_CONFIG_V1", config.get("schema"))
        self.assertEqual([MEDIA_ROOT], config.get("read_roots"))
        self.assertEqual([MEDIA_ROOT], config.get("write_roots"))
        self.assertFalse(config.get("process", {}).get("enabled"))
        self.assertEqual([], config.get("process", {}).get("allowed_executables"))
        self.assertEqual([], config.get("process", {}).get("working_roots"))


if __name__ == "__main__":
    unittest.main()
