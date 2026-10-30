"""Source bootstrap for the same installed CLI; stdlib only, no installation side effects."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]


def main():
    from forgestra.cli import main as cli

    return cli()


if __name__ == "__main__":
    sys.exit(main())
