"""Deny-only compatibility probe; legacy implementation is not distributed."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))


def _deny_legacy_execution():
    from forgestra_safety import require

    require("target_modification")


_deny_legacy_execution()


def _generate_resource_pages(self, schema):
    from local_generation import write_frontend_pages

    return write_frontend_pages(self.frontend_dir, schema)
