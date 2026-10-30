# Offline quickstart

Use CPython 3.14.3 from the source root. No installation, keys or network are needed.

```powershell
python -I -B scripts/forgestra_cli.py --help
python -I -B scripts/forgestra_cli.py doctor --source .
python -I -B scripts/forgestra_cli.py inspect .
python -I -B scripts/forgestra_cli.py workspace .
python -I -B scripts/forgestra_cli.py config --config config/forgestra.example.json
python -I -B scripts/forgestra_cli.py integrations
python -I -B scripts/forgestra_cli.py release --gate A
```

Expected: help, READY_OFFLINE, INSPECTED_LOCAL, PLANNED_LOCAL, VALID, AVAILABLE_LOCAL,
BLOCKED. Release assessment intentionally exits 1. Plans never execute their proposed
commands or authorize publication. Invalid input fails closed.

See [installation](INSTALL.md), [capabilities](CAPABILITIES.md),
[verification profiles](VERIFICATION.md) and [release policy](RELEASE.md).
