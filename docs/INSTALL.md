# Installation and checks

Use CPython 3.14.3. The source CLI needs no installation, SDK, credentials or network.
Run the seven commands in the [quickstart](QUICKSTART.md) from the source root.
Do not run inactive legacy installers.

## Tool acquisition

Public product validation also requires Node 24.14.0, Git, Bash and the locked
Python/native/npm/browser/optional-SDK tools. Install supported Python/Node/Git/Bash
through your reviewed operating-system setup first. No system services are required.
These reviewed commands acquire public, pinned development artifacts; they do not
call providers or install customer dependencies:

On Windows use a short, trusted temporary directory to keep pip's nested build
paths below the Windows path limit. For example, create `.tools/t` in a short
checkout, then set `$env:TEMP`, `$env:TMP` and `$env:TMPDIR` to its absolute path
before these commands. GitHub CI uses the runner's temporary directory. This
temporary-directory choice does not provide OS isolation for customer code.

```powershell
python -I scripts/acquire_tools.py --download
python -I scripts/bootstrap.py --wheelhouse .tools/wheels
python -I scripts/pr06_web_validation.py --acquire --download
python -I scripts/pr10_mcp_validation.py --acquire --download
python -I scripts/public_checks.py
```

For offline replay, supply hash-matching wheels/native archives and the documented
integrity-locked web/SDK caches in their .tools locations; omit --download during
acquisition verification. The validation itself uses only authored loopback traffic.
Missing or changed tools fail; nothing is downloaded on import, doctor or inspection.
The public checker refuses existing .tools/public-results; retain an earlier result
outside that output path before a separately reviewed rerun. Do not remove user files.

The gate creates fresh build/install environments, builds wheels twice, builds a
source distribution and installs both actual artifacts offline. It checks exact
members, source-preserving quickstart, regressions, lint/types/workflows and all
authored fixture boundaries. Private audits/evidence are not contributor prerequisites.

## Installing a locally reviewed artifact

No registry upload is authorized. With an owner-reviewed local wheel:

```powershell
python -I -m venv --copies .local-core
.local-core/Scripts/python.exe -I -m pip --isolated --no-cache-dir install --no-index --no-deps PATH_TO_REVIEWED_WHEEL
.local-core/Scripts/python.exe -I -m forgestra doctor
```

On Linux replace Scripts/python.exe with bin/python. Installing the source tarball
offline additionally requires setuptools from requirements/build.lock in the fresh
environment, then pip --no-index --no-deps --no-build-isolation with the reviewed
tarball. Source doctor and product CI apply to the complete source tree, not an
arbitrary installed site-packages directory. The core runtime needs no keys.

See [MCP setup](MCP.md), [verification profiles](VERIFICATION.md)
and [rights guidance](PROVENANCE.md). Lifecycle scripts, telemetry and privileged
automation stay disabled. Filtered fixed-fixture processes are not an OS sandbox.
