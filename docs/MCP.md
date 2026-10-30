# Optional read-only MCP

The core CLI needs no SDK or keys. The separate forgestra-mcp package exposes
factory_status, bounded inspect_workspace and fictional sales_demo via client-spawned
stdio. Root is chosen at process startup, never from tool arguments. No workflow,
publisher, outreach, provider or arbitrary command tool is exposed. mcp.json stays empty.

After [reviewed acquisition](INSTALL.md), create a separate venv with --copies,
install locked SDK wheels using requirements/mcp.lock with --no-index --require-hashes
--only-binary=:all:, and install the reviewed core/optional wheels with --no-deps.
The optional package's source is integrations/mcp; never use the dormant legacy servers.
The public gate exercises the exact clean optional wheel and SDK protocol session.

```powershell
OPTIONAL_PYTHON -I -m forgestra_mcp --root ABSOLUTE_REVIEWED_ROOT
```

Emit a read-only client configuration with core integrations --client-python
ABSOLUTE_OPTIONAL_PYTHON --root ABSOLUTE_REVIEWED_ROOT; it is NOT_APPLIED. The
interpreter and all ancestors must be unlinked. Actual editor registration is NOT_RUN.
No persistent server/VPS is needed. See [capabilities](CAPABILITIES.md).
