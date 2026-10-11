"""Exercise verify.sh control flow without Apple tools or signing credentials.

Run: python3 -m unittest discover -s packaging/macos/tests -v
The shims test shipped-app verification and cleanup, not macOS signature validity.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="photocraft verify test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        packaging = self.root / "packaging"
        (packaging / "macos").mkdir(parents=True)
        shutil.copy(SCRIPTS / "verify.sh", packaging / "macos")
        shutil.copy(SCRIPTS.parent / "env.sh", packaging)
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.0.0"\n')
        dist = self.root / "dist"
        dist.mkdir()
        for name in ("photocraft-0.0.0-macos-aarch64.dmg", "photocraft-cli-0.0.0-macos-aarch64.zip"):
            (dist / name).touch()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands.log"
        self.env = os.environ.copy()
        for key in ("APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID", "GITHUB_STEP_SUMMARY",
                    "MACOS_KEYCHAIN", "CRAFT_FONTS_DIR", "CRAFT_FONTS_REQUIRED"):
            self.env.pop(key, None)
        self.env.update(PATH=f"{self.bin}{os.pathsep}{self.env['PATH']}",
                        DIST=str(dist), RUNNER_TEMP=str(self.root),
                        PHOTOCRAFT_VERSION="0.0.0", PHOTOCRAFT_BUILD_SHA="test",
                        MACOS_SIGN_IDENTITY="-", TEST_LOG=str(self.log), TEST_CASE="ok")
        self.shim("ditto", '''
mkdir -p "$4/photocraft-cli-0.0.0-macos-aarch64"
printf '#!/bin/sh\nexit 0\n' > "$4/photocraft-cli-0.0.0-macos-aarch64/photocraft-cli"
chmod +x "$4/photocraft-cli-0.0.0-macos-aarch64/photocraft-cli"
''')
        self.shim("lipo", "echo arm64\n")
        self.shim("spctl", "echo 'source=Notarized Developer ID'\n")
        self.shim("xcrun", '''
case "$*" in
  *PhotoCraft.app*) [ "$TEST_CASE" != missing_ticket ] ;;
esac
''')
        self.shim("codesign", '''
case "$*" in
  *PhotoCraft.app*) [ "$TEST_CASE" != bad_signature ] ;;
  '-d '*) printf 'CodeDirectory flags=0x10000(runtime)\nAuthority=Developer ID Application: Test\nTimestamp=Test\nTeamIdentifier=TEST\n' ;;
esac
''')
        self.shim("hdiutil", '''
case "$1" in
  attach)
    [ "$TEST_CASE" != attach_failure ] || exit 1
    [ "$TEST_CASE" = missing_app ] || mkdir -p "$5/PhotoCraft.app"
    ;;
  detach)
    if [ "$TEST_CASE" = detach_retry ] && [ "$2" != -force ]; then exit 1; fi
    ;;
  *) exit 2 ;;
esac
''')

    def shim(self, name, body):
        script = self.bin / name
        script.write_text('#!/usr/bin/env bash\nset -eu\n'
                          f'printf "%s\\n" "{name} $*" >> "$TEST_LOG"\n' + body)
        script.chmod(0o755)

    def run_verify(self, case):
        self.env["TEST_CASE"] = case
        result = subprocess.run(["bash", str(self.root / "packaging/macos/verify.sh"),
                                 "--arch", "aarch64"], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(list(self.root.glob("photocraft-verify.*")), [], result.stderr)
        return result, self.log.read_text().splitlines()

    def test_checks_shipped_app_and_detaches_on_success(self):
        result, calls = self.run_verify("ok")
        self.assertEqual(result.returncode, 0, result.stderr)
        app_checks = [call for call in calls if call.startswith("codesign --verify")
                      and call.endswith("PhotoCraft.app")]
        self.assertEqual(len(app_checks), 1)
        self.assertIn("--strict --deep", app_checks[0])
        self.assertTrue(any(call.startswith("hdiutil attach -readonly -nobrowse") for call in calls))
        self.assertTrue(calls[-1].startswith("hdiutil detach "))

    def test_bad_app_signature_fails_even_without_secrets_and_detaches(self):
        result, calls = self.run_verify("bad_signature")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("==> verified:", result.stdout)
        self.assertTrue(calls[-1].startswith("hdiutil detach "))

    def test_missing_app_fails_and_detaches(self):
        result, calls = self.run_verify("missing_app")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no PhotoCraft.app", result.stderr)
        self.assertTrue(calls[-1].startswith("hdiutil detach "))

    def test_failed_attach_does_not_try_to_detach(self):
        result, calls = self.run_verify("attach_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("hdiutil detach") for call in calls))

    def test_retries_detach_with_force(self):
        result, calls = self.run_verify("detach_retry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls[-2].startswith("hdiutil detach "))
        self.assertTrue(calls[-1].startswith("hdiutil detach -force "))

    def test_signed_release_checks_app_ticket_and_gatekeeper(self):
        self.env.update(MACOS_SIGN_IDENTITY="Test identity", APPLE_ID="test@example.invalid",
                        APPLE_PASSWORD="test-password", APPLE_TEAM_ID="TEST")
        result, calls = self.run_verify("ok")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(call.startswith("xcrun stapler validate ")
                            and call.endswith("PhotoCraft.app") for call in calls))
        self.assertTrue(any(call.startswith("spctl --assess --type execute ")
                            and call.endswith("PhotoCraft.app") for call in calls))
        result, calls = self.run_verify("missing_ticket")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no notarization ticket stapled to PhotoCraft.app", result.stderr)
        self.assertTrue(calls[-1].startswith("hdiutil detach "))


if __name__ == "__main__":
    unittest.main()
