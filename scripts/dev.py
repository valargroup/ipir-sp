#!/usr/bin/env python3
"""Run Cargo with a nonblocking, reusable target-directory lease (macOS/Linux)."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {"build", "check", "test", "clippy", "bench", "doc"}


def identity() -> str:
    """Partition toolchains/flags; Cargo fingerprints packages, features and profiles."""
    rust = subprocess.check_output(["rustc", "-vV"], cwd=ROOT)
    settings = {key: value for key, value in os.environ.items()
                if key.startswith("CARGO_") or key in {
                    "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER",
                    "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN"}}
    settings.pop("CARGO_TARGET_DIR", None)
    # Include the checkout even when multiple worktrees share a custom build root.
    return hashlib.sha256(rust + str(ROOT).encode() +
                          json.dumps(settings, sort_keys=True).encode()).hexdigest()[:20]


class Lease:
    """Try slots in order; never wait on another owner or unlink a lock inode."""
    def __init__(self, root: Path):
        self.root = root
        self.lock = None
        self.path = None

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        for slot in range(1024):
            path = self.root / str(slot)
            path.mkdir(exist_ok=True)
            lock = (path / ".lease").open("a+")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock.close()
                continue
            self.lock, self.path = lock, path
            return self
        raise RuntimeError("all 1024 target slots are busy")

    def __exit__(self, *exc):
        # Do not LOCK_UN: the supervisor/children may still own this description.
        self.lock.close()


def group_alive(pgid: int) -> bool:
    """Check live group members, excluding zombies which cannot touch the cache."""
    output = subprocess.check_output(["ps", "-axo", "pgid=,stat="], text=True)
    return any(int(parts[0]) == pgid and not parts[1].startswith("Z")
               for line in output.splitlines() if len(parts := line.split()) == 2)


def supervise(fd: int, argv: list[str]) -> int:
    """Hold the inherited lease until Cargo's entire process group finishes.

    Cargo gets its own session. The detached supervisor survives launcher SIGKILL;
    ordinary termination is forwarded to Cargo's group without releasing early.
    The descriptor is also inherited by Cargo as an additional ownership guard.
    """
    process = None
    pending = []

    def forward(signum, _frame):
        if process is None:
            pending.append(signum)
        else:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, forward)
    try:
        process = subprocess.Popen(argv, cwd=ROOT, pass_fds=(fd,), start_new_session=True)
        for signum in pending:
            forward(signum, None)
        code = process.wait()
        # A Cargo child can close inherited descriptors and outlive Cargo itself.
        while group_alive(process.pid):
            time.sleep(0.1)
        return code if code >= 0 else 128 - code
    finally:
        os.close(fd)


def execute(argv: list[str]) -> int:
    """Pass Cargo arguments unchanged except for exclusive target-directory routing."""
    if not argv or argv[0] not in COMMANDS:
        raise ValueError("usage: python3 scripts/dev.py {build,check,test,clippy,bench,doc} [Cargo arguments]")
    cargo_options = argv[:argv.index("--")] if "--" in argv else argv
    if any(arg == "--target-dir" or arg.startswith("--target-dir=") for arg in cargo_options):
        raise ValueError("--target-dir is managed by dev.py; use IPIR_SP_BUILD_ROOT instead")
    root = Path(os.environ.get("IPIR_SP_BUILD_ROOT", str(ROOT / "target" / "dev"))).expanduser().resolve()
    with Lease(root / identity()) as lease:
        command = ["cargo", argv[0], "--target-dir", str(lease.path), *argv[1:]]
        print(f"build directory: {lease.path}", flush=True)
        env = dict(os.environ, CARGO_TARGET_DIR=str(lease.path))
        worker = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--supervise",
             str(lease.lock.fileno()), *command], cwd=ROOT, env=env,
            pass_fds=(lease.lock.fileno(),), start_new_session=True)

        def forward(signum, _frame):
            try:
                worker.send_signal(signum)
            except ProcessLookupError:
                pass

        previous = {sig: signal.signal(sig, forward)
                    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            return worker.wait()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def main() -> int:
    if sys.argv[1:2] == ["--supervise"]:
        return supervise(int(sys.argv[2]), sys.argv[3:])
    try:
        return execute(sys.argv[1:])
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"development command failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
