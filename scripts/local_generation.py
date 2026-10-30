"""Local-only generation adapters shared with contained legacy writers.

Trusted callers enter private_output_workspace() and supply a new directory
immediately inside it. Arbitrary destinations fail closed. This does not approve
running generated code, customer changes, provider calls or publication.
"""

import re
from forgestra_safety import Blocked, ENV_EXAMPLE, write_new_tree


def write_creator_output(destination, files):
    return write_new_tree(destination, files)


def write_frontend_output(destination, resources):
    if not isinstance(resources, list) or not resources:
        raise Blocked("BLOCKED: invalid resource manifest")
    files = [{"path": ".env.example", "content": ENV_EXAMPLE}]
    for resource in resources:
        if not isinstance(resource, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", resource):
            raise Blocked("BLOCKED: invalid resource identifier")
        files.append(
            {
                "path": f"src/pages/{resource}/list.tsx",
                "content": (
                    "// Local scaffold only; backend integration NOT_RUN.\n"
                    f"export default function Page() {{ return <div>{resource}</div>; }}\n"
                ),
            }
        )
    return write_new_tree(destination, files)


def write_frontend_pages(destination, schema):
    """Legacy resource writer adapter: validate every identifier before output."""
    if not isinstance(schema, dict) or not isinstance(schema.get("resources"), list):
        raise Blocked("BLOCKED: invalid schema")
    names = []
    for resource in schema["resources"]:
        if (
            not isinstance(resource, dict)
            or not isinstance(resource.get("label"), str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", resource["label"])
        ):
            raise Blocked("BLOCKED: invalid resource label")
        names.append(resource.get("name"))
    return write_frontend_output(destination, names)
