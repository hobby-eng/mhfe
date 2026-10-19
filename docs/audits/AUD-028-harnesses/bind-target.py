#!/usr/bin/env python3
"""Observe the bind wrapper operand without compiling or binding any WASM."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        raise ValueError("Give an existing workspace scratch directory")
    root = Path(__file__).resolve().parents[3]
    cargo = shutil.which("cargo")
    if not cargo:
        raise ValueError("The workspace Cargo toolchain must be on PATH")
    temporary = tempfile.TemporaryDirectory(
        dir=sys.argv[1], prefix="bind-probe-",
    )
    with temporary as folder:
        scratch = Path(folder)
        env = dict(os.environ)
        env.pop("CARGO_TARGET_DIR", None)
        env["CARGO_BUILD_TARGET_DIR"] = str(scratch / "configured-target")
        result = subprocess.run(
            [cargo, "metadata", "--locked", "--no-deps",
             "--format-version", "1"], cwd=root, env=env,
            check=True, capture_output=True, text=True, timeout=15,
        )
        target = Path(json.loads(result.stdout)["target_directory"])
        expected = target / "wasm32-unknown-unknown/release/mhfe.wasm"
        shims = scratch / "commands"
        shims.mkdir()
        observer = '''import json, os, subprocess, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == "wasm-bindgen" and args == ["--version"]:
    print("wasm-bindgen 0.2.129")
elif name == "wasm-bindgen":
    Path(os.environ["AUDIT_BIND_ARGS"]).write_text(json.dumps(args))
    sys.exit(77)
elif args and args[0] == "rustc":
    Path(os.environ["AUDIT_CARGO_ARGS"]).write_text(json.dumps(args))
elif args == ["metadata", "--locked", "--no-deps",
              "--format-version", "1"]:
    sys.exit(subprocess.call([os.environ["AUDIT_REAL_CARGO"], *args]))
else:
    raise RuntimeError("Observer refuses an unexpected Cargo command")
'''
        for name in ("cargo", "wasm-bindgen"):
            path = shims / name
            path.write_text("#!" + sys.executable + "\n" + observer)
            path.chmod(0o700)
        env.update({
            "PATH": str(shims) + os.pathsep + env["PATH"],
            "AUDIT_REAL_CARGO": cargo,
            "AUDIT_CARGO_ARGS": str(scratch / "cargo.json"),
            "AUDIT_BIND_ARGS": str(scratch / "bind.json"),
        })
        sentinel = scratch / "dispatched"
        fake_cargo = scratch / "unexpected-cargo"
        fake_cargo.write_text(
            "#!" + sys.executable + "\nfrom pathlib import Path\n" +
            "Path(" + repr(str(sentinel)) + ").write_text('dispatched')\n",
        )
        fake_cargo.chmod(0o700)
        control_env = dict(env, AUDIT_REAL_CARGO=str(fake_cargo))
        for command in ("build", "check"):
            control = subprocess.run(
                [str(shims / "cargo"), command], env=control_env,
                capture_output=True, text=True, timeout=5,
            )
            if control.returncode == 0 or sentinel.exists():
                raise RuntimeError("Observer dispatched an unsafe command")
        print("PASS: observer refuses build/check before external dispatch")
        result = subprocess.run(
            ["bash", "scripts/bind-wasm.sh", "wasm",
             str(scratch / "output")], cwd=root, env=env,
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 77:
            raise RuntimeError("Wrapper did not reach the binding observer")
        compile_args = json.loads((scratch / "cargo.json").read_text())
        if compile_args[0] != "rustc" or "--locked" not in compile_args:
            raise RuntimeError("Expected locked Cargo build request")
        operand = json.loads((scratch / "bind.json").read_text())[0]
        observed = (root / operand).resolve()
        print(json.dumps({"expected": str(expected),
                          "observed": str(observed),
                          "compiled": False, "bound": False}, indent=2))
        if observed != expected:
            raise RuntimeError("Binding input ignores Cargo target directory")
    print("PASS: binding operand follows actual Cargo target configuration")


if __name__ == "__main__":
    main()
