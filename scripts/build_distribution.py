"""Build the reviewed source distribution; no target hooks or network resolution."""

import os
from importlib import import_module
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]


def main():
    from forgestra.verification import validate_source

    validate_source(ROOT)
    build_meta = import_module("setuptools.build_meta")
    os.chdir(ROOT)
    destination = ROOT / ".tools/distributions"
    destination.mkdir(parents=True, exist_ok=False)
    build_meta.build_sdist(str(destination))


if __name__ == "__main__":
    main()
