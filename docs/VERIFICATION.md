# Verification profiles

## Public product checks

Run python -I scripts/public_checks.py after the [documented tool setup](INSTALL.md).
The profile FORGESTRA_PUBLIC_PRODUCT_V1 requires private archives physically absent,
a pinned authored entrypoint inventory, reviewed source/build/lock contracts and
all meaningful existing safety regressions. Historical-recorder rejection tests
use disposable, explicitly synthetic bytes. The MCP evidence-mutation test executes
a fresh actual SDK fixture instead of reading a historical captured receipt.

The nineteen inner CI commands remain mandatory; additional fixture, artifact and
link checks are required too. Zero tests, skips, expected failures and changed input
hashes fail. A failed run exports only finite structured status/digest records.
The archive inspector requires every proposed source file byte in the tarball,
checks wheel source bytes and every RECORD digest, and permits only an exact set
of generated metadata files. Omitted source, extra metadata code and rehashed
altered wheel payloads fail. Detailed current fixture receipts are retained outside
the upload directory, including failed receipts; an empty inner log fails closed.
Only summary.json, artifacts.json and sbom.json in .tools/public-results/upload
are upload candidates; no raw logs, argv, private inventories or owner decisions.
The upload checker rejects extra files, links, arbitrary child details and private
profile substitution. The source-input SBOM is not advisory/license clearance.

## Private maintainer evidence replay

This separate command requires an explicitly supplied, privately retained baseline:

```powershell
python -I scripts/private_evidence.py --root PRIVATE_SOURCE_ROOT --inventory PRIVATE_EXPECTED_INVENTORY
```

Its FORGESTRA_PRIVATE_MAINTAINER_V1 receipt verifies exact supplied historical bytes,
including required accepted phase manifests/reports and original audits. Missing,
changed, linked or mismatched data blocks; it never silently becomes a public run.
The inventory and private archive are not shipped with public artifacts. It does
not manufacture original history, new owner decisions or release approval.

## Coverage reconciliation

| Old dependency/assertion | Public replacement | Private preservation |
| --- | --- | --- |
| PR 01 containment archive enumerates guarded entrypoints | Pinned authored [inventory](../tests/fixtures/public/containment.json), same actual import/CLI denial assertions | Original archive bytes remain in private replay |
| PR 01 local-tools metadata | Public CI verifies native archives and wheel locks from reviewed config; provenance rejection tests retain disposable synthetic input | Original private tooling receipts remain pinned |
| PR 02 baselines/provenance and original audits | Public CI validates product source/locks/test outcomes directly; recorder negative tests use synthetic private trees | Exact accepted archive/audit byte replay remains required privately |
| PR 10 historical MCP receipt | Fresh actual SDK/stdio session plus unchanged numeric/log/argv mutation assertions | Captured historical receipt stays privately pinned |
| PR 11 decisions/baselines / source continuity | Current public source digest, private-absent profile, fresh fixtures and immutable artifact hashes; release always blocked | Owner decisions and historical provenance remain separate private inputs |
| Whole-directory artifact upload | Positive three-file structured allowlist, success/failure and tamper tests | Raw current logs and original archives retained privately |

Windows local acceptance is distinct from Linux or GitHub-hosted acceptance. The
workflow proposes ubuntu-24.04/windows-2025 public-product jobs. Actual status-check
names/enforcement must come from future authorized runs, not nineteen inner commands.
No token/provider key presence turns an unrun check into acceptance.
