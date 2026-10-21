#!/usr/bin/env python3
"""Verify the upgrade fixture's exact image pin and POSIX context selection."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "integration-tests/test-authorization-upgrade.sh"


class UpgradeContextTests(unittest.TestCase):
    def test_actual_posix_context_assignment_preserves_default_and_explicit_path(self):
        assignment = next(line for line in SCRIPT.read_text().splitlines()
                          if line.startswith("current_build_context="))
        with tempfile.TemporaryDirectory(prefix="upgrade-context-") as temporary:
            root = Path(temporary)
            source, prepared = root / "source checkout", root / "verified context"
            source.mkdir()
            prepared.mkdir()
            for override, expected in ((None, source), ("", source), (str(prepared), prepared)):
                env = dict(os.environ, REPO_FIXTURE=str(source))
                env.pop("CURRENT_BUILD_CONTEXT", None)
                if override is not None:
                    env["CURRENT_BUILD_CONTEXT"] = override
                actual = subprocess.check_output(
                    ["sh", "-eu", "-c", 'repo_dir="$REPO_FIXTURE"\n' + assignment +
                     '\nprintf "%s" "$current_build_context"'], env=env, text=True, timeout=10)
                self.assertEqual(actual, str(expected))

    def test_current_build_uses_explicit_context_but_legacy_remains_exact_archive(self):
        script = SCRIPT.read_text()
        self.assertIn('docker build -q -t "$casbin_image" "$current_build_context"', script)
        self.assertIn('git -C "$repo_dir" archive "$legacy_ref" | tar -x -C "$temp_dir"', script)
        self.assertIn('docker build -q -t "$legacy_image" "$temp_dir"', script)
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True, capture_output=True, timeout=10)

    def test_spicedb_fixture_is_the_exact_reviewed_index(self):
        script = SCRIPT.read_text()
        images = [word for word in script.split() if word.startswith("authzed/spicedb:")]
        self.assertEqual(images, ["authzed/spicedb:v1.45.4@sha256:cad9887e8c0335f06dbaf6a7db8011a666075e6fe143c5181ddbc258280d1e23"])


if __name__ == "__main__":
    unittest.main()
