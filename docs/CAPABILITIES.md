# Capability matrix

| Interface / claim | Classification | Code | Tests |
| --- | --- | --- | --- |
| help, doctor, inspect, config, workspace | Implemented local read-only core | [CLI](../src/forgestra/cli.py) | [Core tests](../tests/test_pr02.py) |
| assess, audit, improve | Experimental advisory offline replay; live providers disabled | [Assessment](../src/forgestra/assessment.py) | [Parser/error tests](../tests/test_pr03.py) |
| adopt plans | Implemented read-only plan; transition execution authored fixture only | [Adoption](../src/forgestra/adoption.py) | [Preservation tests](../tests/test_pr05.py) |
| web plan and generated app validation | Deterministic authored fixture only; not real Hasura/OIDC/container acceptance | [Web](../src/forgestra/web.py) | [Web tests](../tests/test_pr06.py) |
| create plan / component reuse | Read-only plan; one private tested product fixture only | [Creation](../src/forgestra/creation.py) | [Creation tests](../tests/test_pr07.py) |
| sync, sync-baseline, sync-targets | Read-only three-way plans/enumeration; private staging fixture only | [Sync](../src/forgestra/synchronization.py) | [Conflict tests](../tests/test_pr08.py) |
| maintain | Read-only review; private repair/refactor fixture only | [Maintenance](../src/forgestra/maintenance.py) | [Maintenance tests](../tests/test_pr09.py) |
| integrations / optional MCP | Locally verified read-only stdio; editor registration not live-verified | [Adapter](../integrations/mcp/src/forgestra_mcp/server.py) | [SDK tests](../tests/test_pr10.py) |
| release | Read-only BLOCKED assessment; never publication authority | [Release](../src/forgestra/release.py) | [Release tests](../tests/test_pr11.py) |
| repair / install / customer mutation / publisher | Unavailable: trusted approval, OS isolation and remote publisher absent | [Deny controls](../scripts/forgestra_safety.py) | [Safety tests](../tests/test_safety.py) |
| Workik / Lovable / mobile / autonomous sales | Planned/dormant; sales is fictional demo only | [Catalogue](../src/forgestra/integrations.py) | [Integration tests](../tests/test_pr10.py) |

Accepted historical PR 01–11 local scopes demonstrated containment and fixtures,
not completion of the original production workflow. Those acceptances are retained
privately. No disabled capability is described as implemented. [Runtime backlog](RUNTIME_BACKLOG.md)
retains the broader production factory goal. No persistent factory hosting is required
for this limited CLI/stdio scope; generated applications are separate products.
