"""Explicit public, hash-checked tooling acquisition. Never runs an installer script."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[1]


def tool_platform():
    system = platform.system().lower()
    if system not in {"windows", "linux"} or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("unsupported native tool platform")
    return system


def unlinked(path):
    for item in [path, *path.parents]:
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("linked tool directory unsupported")


def extract_verified(data, specification):
    if hashlib.sha256(data).hexdigest() != specification["sha256"]:
        raise ValueError("native archive checksum mismatch")
    name = specification["member"]
    if specification["url"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.getinfo(name).file_size > 100_000_000:
                raise ValueError("oversized native tool")
            return archive.read(name)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        member = archive.getmember(name)
        if not member.isreg() or member.size > 100_000_000:
            raise ValueError("unsupported archive member")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("missing native tool")
        return stream.read()


def native_tools(download=False):
    specs = json.loads((ROOT / "config/toolchain.json").read_text())["native"][tool_platform()]
    directory = ROOT / ".tools/pr02-native"
    unlinked(directory)
    directory.mkdir(parents=True, exist_ok=True)
    output = {}
    for name, spec in specs.items():
        archive_path = directory / spec["url"].rsplit("/", 1)[1]
        unlinked(archive_path)
        if not archive_path.is_file():
            if not download:
                raise ValueError("native archive unavailable; explicit acquisition required")
            if not spec["url"].startswith("https://github.com/"):
                raise ValueError("unsupported download origin")
            with urllib.request.urlopen(spec["url"], timeout=30) as response:
                data = response.read(100_000_001)
            if len(data) > 100_000_000:
                raise ValueError("oversized native archive")
            # Validate before retaining or extracting an archive.
            extract_verified(data, spec)
            archive_path.write_bytes(data)
        payload = extract_verified(archive_path.read_bytes(), spec)
        executable = directory / (name + (".exe" if sys.platform == "win32" else ""))
        unlinked(executable)
        if not executable.exists() or executable.read_bytes() != payload:
            executable.write_bytes(payload)
            executable.chmod(0o755)
        output[name] = str(executable)
    return output


def main():
    from bootstrap import environment
    from forgestra.verification import validate_source
    from forgestra_safety import Blocked

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="Explicit public HTTPS acquisition")
    args = parser.parse_args()
    try:
        validate_source(ROOT)
        native_tools(args.download)
        wheels = ROOT / ".tools/wheels"
        unlinked(wheels)
        wheels.mkdir(parents=True, exist_ok=True)
        if args.download:
            argv = [
                sys.executable,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--no-cache-dir",
                "download",
                "--index-url",
                "https://pypi.org/simple",
                "--require-hashes",
                "--only-binary=:all:",
                "--dest",
                str(wheels),
                "-r",
                str(ROOT / "requirements/build.lock"),
                "-r",
                str(ROOT / "requirements/dev.lock"),
            ]
            result = subprocess.run(
                argv, env=environment(), capture_output=True, timeout=180, check=False
            )
            if result.returncode:
                raise ValueError("wheel acquisition failed")
        print(
            json.dumps(
                {
                    "status": "TOOLS_AVAILABLE",
                    "wheels": (
                        "Acquired"
                        if args.download
                        else "Not checked; pip hash gate validates on install"
                    ),
                }
            )
        )
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
        Blocked,
        TypeError,
        SyntaxError,
    ):
        print(json.dumps({"status": "BLOCKED", "reason": "Tool acquisition incomplete"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
