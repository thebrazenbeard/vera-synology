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

    def test_install_wizard_and_stdio_tunnel_contract(self):
        wizard_path = MEDIA / "spk" / "WIZARD_UIFILES" / "install_uifile"
        self.assertTrue(wizard_path.is_file(), "DSM install wizard is missing")
        wizard = json.loads(wizard_path.read_text(encoding="utf-8"))
        subitems = [
            subitem
            for step in wizard
            for item in step.get("items", [])
            for subitem in item.get("subitems", [])
        ]
        by_key = {item.get("key"): item for item in subitems}
        self.assertIn("wizard_tunnel_id", by_key)
        self.assertIn("wizard_runtime_api_key", by_key)

        password_items = [
            item
            for step in wizard
            for item in step.get("items", [])
            if item.get("type") == "password"
        ]
        password_keys = {
            subitem.get("key")
            for item in password_items
            for subitem in item.get("subitems", [])
        }
        self.assertIn("wizard_runtime_api_key", password_keys)

        postinst_path = MEDIA / "spk" / "scripts" / "postinst"
        self.assertTrue(postinst_path.is_file(), "postinst credential handoff is missing")
        postinst = postinst_path.read_text(encoding="utf-8")
        self.assertIn("SYNOPKG_WZF_wizard_tunnel_id", postinst)
        self.assertIn("SYNOPKG_WZF_wizard_runtime_api_key", postinst)
        self.assertIn("umask 077", postinst)
        self.assertIn('chmod 600 "$TUNNEL_ID_FILE"', postinst)
        self.assertIn('chmod 600 "$API_KEY_FILE"', postinst)
        self.assertNotIn("echo $API_KEY", postinst)
        self.assertNotIn("echo \${API_KEY}", postinst)

        launcher_path = MEDIA / "payload" / "bin" / "run-workbridge-media.sh"
        self.assertTrue(launcher_path.is_file(), "stdio tunnel launcher is missing")
        launcher = launcher_path.read_text(encoding="utf-8")
        self.assertIn("tunnel-client-runtime", launcher)
        self.assertIn("workbridge-mcp", launcher)
        self.assertIn("--mcp.command", launcher)
        self.assertIn("--control-plane.api-key", launcher)
        self.assertIn("file:$API_KEY_FILE", launcher)
        self.assertIn("--health.listen-addr", launcher)
        self.assertIn("127.0.0.1:17448", launcher)
        self.assertNotIn("--mcp.server-url", launcher)
        self.assertNotIn("WORKBRIDGE_HTTP_TOKEN", launcher)

        service_path = MEDIA / "spk" / "conf" / "systemd" / "pkguser-workbridgemedia.service"
        self.assertTrue(service_path.is_file(), "DSM service unit is missing")
        service = service_path.read_text(encoding="utf-8")
        self.assertIn("ExecStart=/var/packages/WorkBridgeMedia/target/bin/run-workbridge-media.sh", service)
        self.assertIn("UMask=0077", service)


if __name__ == "__main__":
    unittest.main()
