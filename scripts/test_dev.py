"""Process-level regressions for target ownership; no Rust compilation needed."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("dev.py").resolve()
spec = importlib.util.spec_from_file_location("dev", SCRIPT)
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)

FAKE_CARGO = '''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
path = pathlib.Path(sys.argv[sys.argv.index("--target-dir") + 1])
mode = sys.argv[-1]
(path / "argv.json").write_text(json.dumps(sys.argv[1:]))
(path / "pid").write_text(str(os.getpid()))
if mode == "child":
    subprocess.Popen([sys.executable, "-c", "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); (p/'child-ready').touch(); exec(\\\"while not (p/'release').exists(): time.sleep(0.02)\\\")", str(path)], close_fds=True)
    sys.exit(0)
if mode == "hold":
    while not (path / "release").exists(): time.sleep(0.02)
sys.exit(7 if mode == "fail" else 0)
'''


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        binary = self.root / "bin"
        binary.mkdir()
        for name, content in (("cargo", FAKE_CARGO), ("rustc", "#!/bin/sh\necho fixture-toolchain\n")):
            script = binary / name
            script.write_text(content)
            script.chmod(0o755)
        self.env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                        IPIR_SP_BUILD_ROOT=str(self.root / "targets"))
        self.processes = []
        self.addCleanup(self.stop)

    def stop(self):
        for path in self.root.glob("targets/*/*"):
            (path / "release").touch()
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=10)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 10
        while not predicate():
            if time.monotonic() > deadline:
                self.fail("process transition timed out")
            time.sleep(0.02)

    def start(self, mode="hold", args=None):
        process = subprocess.Popen([sys.executable, str(SCRIPT), *(args or ["test", mode])],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        line = process.stdout.readline()
        self.assertTrue(line.startswith("build directory: "), line + process.stderr.read() if process.poll() is not None else line)
        path = Path(line.strip().split(": ", 1)[1])
        self.wait_for(lambda: (path / "pid").exists())
        return process, path

    def finish(self, process, path, code=0):
        (path / "release").touch()
        _, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, code, error)

    def test_concurrent_ownership_and_sequential_reuse(self):
        first, a = self.start()
        second, b = self.start()
        self.assertNotEqual(a, b)
        self.finish(first, a)
        later, c = self.start("done")
        self.assertEqual(a, c)
        self.finish(later, c)
        self.finish(second, b)

    def test_killed_launcher_does_not_release_live_cargo(self):
        owner, a = self.start()
        owner.kill()
        owner.wait(timeout=10)
        contender, b = self.start()
        self.assertNotEqual(a, b)
        self.finish(contender, b)
        os.killpg(int((a / "pid").read_text()), signal.SIGKILL)
        self.wait_for(lambda: self.available(a))
        later, c = self.start("done")
        self.assertEqual(a, c)
        self.finish(later, c)

    def available(self, path):
        # Reopen the SAME inode; the test must never unlock an active owner.
        import fcntl
        with (path / ".lease").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False

    def test_child_closing_fds_outlives_cargo_and_killed_launcher(self):
        owner, a = self.start("child")
        self.wait_for(lambda: (a / "child-ready").exists())
        self.assertIsNone(owner.poll())
        self.assertFalse(self.available(a))
        owner.kill()
        owner.wait(timeout=10)
        contender, b = self.start()
        self.assertNotEqual(a, b)
        self.finish(contender, b)
        (a / "release").touch()
        self.wait_for(lambda: self.available(a))
        later, c = self.start("done")
        self.assertEqual(a, c)
        self.finish(later, c)

    def test_failure_exit_and_argument_preservation(self):
        args = ["test", "-p", "ipir-sp", "--no-default-features", "--features", "experimental-params",
                "--profile", "release", "--", "--exact", "fail"]
        process, path = self.start(args=args)
        self.finish(process, path, code=7)
        actual = json.loads((path / "argv.json").read_text())
        self.assertEqual(actual, [args[0], "--target-dir", str(path), *args[1:]])
        self.assertTrue(self.available(path))

    def test_sigterm_forwards_and_releases(self):
        process, path = self.start()
        process.terminate()
        process.communicate(timeout=10)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
        self.assertTrue(self.available(path))

    def test_target_override_and_unknown_command_rejected(self):
        for args in (["clean"], ["check", "--target-dir", "/tmp/other"],
                     ["test", "--target-dir=/tmp/other"]):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], env=self.env, capture_output=True)
            self.assertEqual(result.returncode, 1)
        self.assertFalse((self.root / "targets").exists())

    def test_exhaustion_is_nonblocking(self):
        leases = []
        try:
            for _ in range(1024):
                leases.append(dev.Lease(self.root / "pool").__enter__())
            with self.assertRaisesRegex(RuntimeError, "busy"):
                dev.Lease(self.root / "pool").__enter__()
        finally:
            for lease in leases:
                lease.__exit__()


if __name__ == "__main__":
    unittest.main()
