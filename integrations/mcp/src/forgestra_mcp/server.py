"""Explicit stdio only, fixed startup root, strict arguments and structured errors."""

import argparse
import asyncio
import json
from importlib import import_module
import os
from pathlib import Path

from forgestra.integrations import TOOLS, dispatch, root_inventory


def build_server(root):
    Server = import_module("mcp.server").Server
    types = import_module("mcp.types")

    root, _ = root_inventory(root)

    async def list_tools(ctx, params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=n,
                    description=d,
                    input_schema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                    output_schema={"type": "object"},
                    annotations=types.ToolAnnotations(
                        read_only_hint=True,
                        destructive_hint=False,
                        idempotent_hint=True,
                        open_world_hint=False,
                    ),
                )
                for n, d in TOOLS.items()
            ]
        )

    async def call_tool(ctx, params):
        result = await asyncio.to_thread(
            dispatch, params.name, {} if params.arguments is None else params.arguments, root
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, sort_keys=True))],
            structured_content=result,
            is_error=result["status"] == "ERROR",
        )

    return Server(
        "Forgestra local read-only",
        version="0.2.0.dev0",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


async def serve(root):
    stdio_server = import_module("mcp.server.stdio").stdio_server

    server = build_server(root)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    # Remove credential variables before importing the optional SDK. This is not OS isolation.
    keep = {
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "FORGESTRA_KILL_SWITCH",
    }
    for name in list(os.environ):
        if name.upper() not in keep:
            del os.environ[name]
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["OTEL_TRACES_EXPORTER"] = "none"
    os.environ["OTEL_METRICS_EXPORTER"] = "none"
    os.environ["OTEL_LOGS_EXPORTER"] = "none"
    try:
        root_inventory(args.root)
        asyncio.run(serve(args.root))
        return 0
    except (OSError, ValueError, RuntimeError):
        # Protocol stdout is never used for a traceback or untrusted input.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
