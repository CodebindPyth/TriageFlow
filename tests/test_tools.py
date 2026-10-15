import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import triageflow


class EnsureToolsTests(unittest.TestCase):
    def test_katana_install_recipe_is_registered(self):
        self.assertEqual(
            triageflow.GO_INSTALLS["katana"],
            "github.com/projectdiscovery/katana/cmd/katana@latest",
        )

    def test_existing_tool_in_custom_gobin_is_not_installed_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / "commands"
            custom_gobin = root / "custom-go-bin"
            custom_gopath_bin = root / "custom-gopath" / "bin"
            default_go_bin = root / "default-go-bin"
            for directory in (commands, custom_gobin, custom_gopath_bin):
                directory.mkdir(parents=True)

            # This fake Go executable returns a non-default GOBIN/GOPATH. Any
            # attempt to run "go install" will fail the test.
            go = commands / "go"
            go.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "env" ]; then\n'
                '  printf "%s\\n%s\\n" "$TEST_GOBIN" "$TEST_GOPATH"\n'
                "  exit 0\n"
                "fi\n"
                'echo "unexpected Go command: $*" >&2\n'
                "exit 91\n",
                encoding="utf-8",
            )
            go.chmod(0o755)

            existing_tool = custom_gobin / "httpx"
            existing_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            existing_tool.chmod(0o755)
            gopath_tool = custom_gopath_bin / "gowitness"
            gopath_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            gopath_tool.chmod(0o755)

            environment = {
                "PATH": str(commands),
                "TEST_GOBIN": str(custom_gobin),
                "TEST_GOPATH": str(root / "custom-gopath"),
            }
            with patch.object(triageflow, "GO_BIN", default_go_bin), patch.dict(
                os.environ, environment, clear=False
            ):
                result = triageflow.ensure_tools(["httpx", "gowitness"])

            self.assertEqual(result, [])
            self.assertTrue(existing_tool.is_file())
            self.assertTrue(gopath_tool.is_file())


if __name__ == "__main__":
    unittest.main()
