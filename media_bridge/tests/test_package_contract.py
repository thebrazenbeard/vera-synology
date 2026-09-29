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

    def test_package_provenance_and_builder_contract(self):
        info_path = MEDIA / "spk" / "INFO"
        self.assertTrue(info_path.is_file(), "SPK INFO is missing")
        info = info_path.read_text(encoding="utf-8")
        self.assertIn('package="WorkBridgeMedia"', info)
        self.assertIn('version="0.1.0-0001"', info)
        self.assertIn('arch="armada38x"', info)

        privilege_path = MEDIA / "spk" / "conf" / "privilege"
        self.assertTrue(privilege_path.is_file(), "package privilege contract is missing")
        privilege = json.loads(privilege_path.read_text(encoding="utf-8"))
        self.assertEqual("package", privilege.get("defaults", {}).get("run-as"))
        self.assertEqual("WorkBridgeMedia", privilege.get("username"))
        self.assertEqual("WorkBridgeMedia", privilege.get("groupname"))

        bindings_path = MEDIA / "component-bindings.json"
        self.assertTrue(bindings_path.is_file(), "component provenance bindings are missing")
        bindings = json.loads(bindings_path.read_text(encoding="utf-8"))
        self.assertEqual("WORKBRIDGE_MEDIA_BINDINGS_V1", bindings.get("schema"))
        self.assertEqual(
            "8e0e9831adc2a6a8d41145c71c8bd64d9a489c77",
            bindings.get("workbridge_mcp", {}).get("commit"),
        )
        self.assertEqual(
            "9be1dc0bd1413f4d63957dda10055db20bd551bdab91bdc2def11ab3bf180da1",
            bindings.get("workbridge_mcp", {}).get("qualified_binary_sha256"),
        )
        self.assertEqual(
            "a390c168ff1b2d14e73a95991c186c6aba3ff5a0",
            bindings.get("openai_tunnel_client", {}).get("commit"),
        )
        self.assertEqual("v0.0.15", bindings.get("openai_tunnel_client", {}).get("tag"))
        self.assertTrue(bindings.get("openai_tunnel_client", {}).get("armv7_derivative"))
        self.assertEqual(
            "3c27d0e9d7dc44488704a3c1687155b7fb5cf80b1fcd3c3d78fac1494229e671",
            bindings.get("openai_tunnel_client", {}).get("qualified_binary_sha256"),
        )

        for path in [
            MEDIA / "third_party" / "openai-tunnel-client-LICENSE",
            MEDIA / "third_party" / "openai-tunnel-client-NOTICE",
            MEDIA / "tools" / "build_spk.py",
            MEDIA / "tools" / "verify_spk.py",
        ]:
            self.assertTrue(path.is_file(), f"required package source missing: {path.relative_to(ROOT)}")

    def test_required_dsm_lifecycle_and_icons_exist(self):
        scripts = [
            "preinst",
            "postinst",
            "preuninst",
            "postuninst",
            "preupgrade",
            "postupgrade",
            "start-stop-status",
        ]
        for name in scripts:
            path = MEDIA / "spk" / "scripts" / name
            self.assertTrue(path.is_file(), f"required DSM lifecycle script missing: {name}")
            self.assertTrue(path.stat().st_mode & 0o111, f"DSM lifecycle script is not executable: {name}")

        for name in ["PACKAGE_ICON.PNG", "PACKAGE_ICON_256.PNG"]:
            path = MEDIA / "spk" / name
            self.assertTrue(path.is_file(), f"required DSM package icon missing: {name}")
            self.assertGreater(path.stat().st_size, 0)

        start_stop = (MEDIA / "spk" / "scripts" / "start-stop-status").read_text(encoding="utf-8")
        self.assertIn("/usr/syno/bin/synosystemctl", start_stop)
        self.assertIn("pkguser-workbridgemedia.service", start_stop)
        self.assertIn("get-active-status", start_stop)

    def test_postinst_respects_resource_timing_and_upgrade_credentials(self):
        postinst = (MEDIA / "spk" / "scripts" / "postinst").read_text(encoding="utf-8")
        self.assertNotIn(
            '[ -d "$ROOT/shares/Media/Library" ]',
            postinst,
            "data-share is not acquired until package enable/start",
        )
        self.assertIn('[ -r "$TUNNEL_ID_FILE" ]', postinst)
        self.assertIn('TUNNEL_ID=$(cat "$TUNNEL_ID_FILE")', postinst)
        self.assertIn('[ -r "$API_KEY_FILE" ]', postinst)
        self.assertIn('API_KEY=$(cat "$API_KEY_FILE")', postinst)

        start_stop = (MEDIA / "spk" / "scripts" / "start-stop-status").read_text(encoding="utf-8")
        self.assertIn('[ -d "$ROOT/shares/Media/Library" ]', start_stop)


if __name__ == "__main__":
    unittest.main()
