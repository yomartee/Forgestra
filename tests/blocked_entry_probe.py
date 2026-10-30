"""Execute a real legacy __main__ with network/process effects denied in child.

Only for the reviewed PR 01 scripts; this is not an arbitrary-code OS sandbox.
"""

import os
import runpy
import socket
import subprocess
import sys
from unittest.mock import patch


def denied(*_args, **_kwargs):
    raise AssertionError("unexpected external effect in offline regression")


def main():
    sys.argv = sys.argv[1:]
    with (
        patch.object(socket, "create_connection", denied),
        patch.object(socket.socket, "connect", denied),
        patch.object(socket.socket, "connect_ex", denied),
        patch.object(subprocess, "Popen", denied),
        patch.object(os, "system", denied),
        patch.object(os, "popen", denied),
    ):
        runpy.run_path(sys.argv[0], run_name="__main__")


if __name__ == "__main__":
    main()
