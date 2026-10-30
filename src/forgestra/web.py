"""Deterministic Next App Router/Hasura generation inside an issued private scope.

Domain JSON is data, never a script or approval. No provider/transport runs here.
"""

import hashlib
import json
from pathlib import Path
import re
from typing import Any

import forgestra_safety as safety
from forgestra.verification import bounded_file

AUTH = {"mode": "hasura-jwt", "cookie": "forgestra_user", "role": "user", "owner_field": "owner_id"}
ASSETS = {
    "layout.txt": "src/app/layout.tsx",
    "providers.txt": "src/app/providers.tsx",
    "home.txt": "src/app/page.tsx",
    "style.txt": "src/app/globals.css",
    "hasura.txt": "src/generated/hasura.ts",
    "provider.txt": "src/generated/provider.ts",
    "server.txt": "src/generated/server.ts",
    "api.txt": "src/app/api/graphql/route.ts",
    "resource.txt": "src/components/resource.tsx",
    "next.txt": "next.config.mjs",
    "eslint.txt": "eslint.config.mjs",
    "tsconfig.json": "tsconfig.json",
    "package.json": "package.json",
    "package-lock.json": "package-lock.json",
    "custom.txt": "src/custom/README.md",
    "contract.txt": "tests/contract.test.mjs",
    "fixture.txt": "tests/backend-fixture.mjs",
    "browser.txt": "tests/browser.mjs",
    "docker.txt": "Dockerfile",
    "dockerignore.txt": ".dockerignore",
    "setup.txt": "SETUP.md",
}
ROOT = Path(__file__).parent / "web_assets"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def identifier(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", value)
        or value.startswith("__")
        or safety.protected(value)
        or any(word in value for word in ("password", "token", "api_key", "admin"))
        or value
        in {
            "api",
            "auth",
            "users",
            "user",
            "sessions",
            "query_root",
            "mutation_root",
            "subscription_root",
            "create",
            "edit",
            "id",
            "owner_id",
            "constructor",
            "prototype",
        }
    ):
        raise safety.Blocked("BLOCKED: unsupported domain identifier")
    return value


def schema(document):
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "name", "authentication", "resources"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["authentication"] != AUTH
    ):
        raise safety.Blocked("BLOCKED: invalid domain/authentication contract")
    identifier(document["name"])
    resources = document["resources"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= 8:
        raise safety.Blocked("BLOCKED: one to eight explicit resources required")
    seen = set()
    root_fields: set[str] = set()
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {"name", "label", "fields"}:
            raise safety.Blocked("BLOCKED: invalid resource contract")
        name = identifier(resource["name"])
        if name in seen:
            raise safety.Blocked("BLOCKED: duplicate resource")
        seen.add(name)
        roots = {
            name,
            name + "_by_pk",
            name + "_aggregate",
            "insert_" + name + "_one",
            "update_" + name + "_by_pk",
            "delete_" + name + "_by_pk",
        }
        if roots & root_fields:
            raise safety.Blocked("BLOCKED: conflicting Hasura root fields")
        root_fields.update(roots)
        label(resource["label"])
        fields = resource["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 8:
            raise safety.Blocked("BLOCKED: explicit scalar fields required")
        names = set()
        for field in fields:
            if (
                not isinstance(field, dict)
                or set(field) != {"name", "label", "type", "nullable"}
                or not isinstance(field["type"], str)
                or field["type"] not in {"string", "number", "boolean"}
                or type(field["nullable"]) is not bool
            ):
                raise safety.Blocked("BLOCKED: unsupported field/relation/enum contract")
            field_name = identifier(field["name"])
            if field_name in names:
                raise safety.Blocked("BLOCKED: duplicate field")
            names.add(field_name)
            label(field["label"])
    if safety.redact(encode(document)) != encode(document):
        raise safety.Blocked("BLOCKED: sensitive domain data")
    return json.loads(encode(document))


def label(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 80
        or any(ord(c) < 32 for c in value)
        or safety.redact(value) != value
    ):
        raise safety.Blocked("BLOCKED: invalid or sensitive display label")


def operations(resource):
    name = resource["name"]
    selection = "id " + " ".join(f["name"] for f in resource["fields"])
    bodies = {
        "list": (
            f"($limit:Int!,$offset:Int!){{rows:{name}"
            f"(limit:$limit,offset:$offset,order_by:{{id:asc}}){{{selection}}}"
            f" aggregate:{name}_aggregate{{aggregate{{count}}}}}}"
        ),
        "get": f"($id:uuid!){{item:{name}_by_pk(id:$id){{{selection}}}}}",
        "create": (
            f"($object:{name}_insert_input!){{item:insert_{name}_one"
            f"(object:$object){{{selection}}}}}"
        ),
        "update": (
            f"($id:uuid!,$patch:{name}_set_input!){{item:update_{name}_by_pk"
            f"(pk_columns:{{id:$id}},_set:$patch){{{selection}}}}}"
        ),
        "delete": f"($id:uuid!){{item:delete_{name}_by_pk(id:$id){{{selection}}}}}",
    }
    return [
        {
            "resource": name,
            "kind": kind,
            "name": name + "_" + kind,
            "query": ("query " if kind in {"list", "get"} else "mutation ")
            + name
            + "_"
            + kind
            + body,
        }
        for kind, body in bodies.items()
    ]


def domain_files(document):
    all_operations = [op for r in document["resources"] for op in operations(r)]
    domain = (
        "export interface DomainRecord { id: string; [key: string]: unknown }\n"
        "export interface Field { name: string; label: string; "
        'type: "string"|"number"|"boolean"; nullable: boolean }\n'
        "export interface Resource { name: string; label: string; fields: Field[] }\n"
        "export interface Operation { name: string; resource: string; "
        'kind: "list"|"get"|"create"|"update"|"delete"; query: string }\n'
        + "export const projectName = "
        + json.dumps(document["name"])
        + ";\n"
        + "export const resources: Resource[] = "
        + encode(document["resources"]).strip()
        + ";\n"
        + "export const operations: Operation[] = "
        + encode(all_operations).strip()
        + ";\n"
    )
    models = []
    mapping = []
    for r in document["resources"]:
        name = r["name"]
        typename = "".join(p.title() for p in name.split("_")) + "Record"
        fields = "; ".join(
            f["name"] + ": " + f["type"] + (" | null" if f["nullable"] else "") for f in r["fields"]
        )
        models.append(f"export interface {typename} {{ id: string; {fields} }}\n")
        insert = f'Omit<{typename}, "id">'
        for kind, variables, data in (
            (
                "list",
                "{ limit: number; offset: number }",
                f"{{ rows: {typename}[]; aggregate: {{ aggregate: {{ count: number }} }} }}",
            ),
            ("get", "{ id: string }", f"{{ item: {typename} | null }}"),
            ("create", "{ object: " + insert + " }", f"{{ item: {typename} }}"),
            (
                "update",
                "{ id: string; patch: Partial<" + insert + "> }",
                f"{{ item: {typename} | null }}",
            ),
            ("delete", "{ id: string }", f"{{ item: {typename} | null }}"),
        ):
            mapping.append(f'  "{name}_{kind}": {{ variables: {variables}; data: {data} }};')
    return (
        domain,
        "".join(models) + "export interface OperationTypes {\n" + "\n".join(mapping) + "\n}\n",
    )


def backend_files(document):
    sql = []
    tables = []
    for resource in document["resources"]:
        name = resource["name"]
        columns = [f["name"] for f in resource["fields"]]
        fields = ", ".join(
            '"'
            + f["name"]
            + '" '
            + {"string": "text", "number": "numeric", "boolean": "boolean"}[f["type"]]
            + ("" if f["nullable"] else " NOT NULL")
            for f in resource["fields"]
        )
        sql.append(
            f'CREATE TABLE public."{name}" '
            f"(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), owner_id uuid NOT NULL, {fields});"
        )
        own = {"owner_id": {"_eq": "X-Hasura-User-Id"}}
        tables.append(
            {
                "table": {"schema": "public", "name": name},
                "select_permissions": [
                    {
                        "role": "user",
                        "permission": {
                            "columns": ["id", *columns],
                            "filter": own,
                            "allow_aggregations": True,
                        },
                    }
                ],
                "insert_permissions": [
                    {
                        "role": "user",
                        "permission": {
                            "columns": columns,
                            "check": own,
                            "set": {"owner_id": "x-hasura-user-id"},
                        },
                    }
                ],
                "update_permissions": [
                    {
                        "role": "user",
                        "permission": {"columns": columns, "filter": own, "check": own},
                    }
                ],
                "delete_permissions": [{"role": "user", "permission": {"filter": own}}],
            }
        )
    metadata = {
        "version": 3,
        "sources": [
            {
                "name": "default",
                "kind": "postgres",
                "configuration": {
                    "connection_info": {
                        "database_url": {"from_env": "HASURA_DATABASE_URL"},
                        "isolation_level": "read-committed",
                        "use_prepared_statements": True,
                    }
                },
                "tables": tables,
            }
        ],
    }
    return "\n".join(sql) + "\n", encode(metadata)


def load_assets():
    catalog = safety.strict_json_loads(bounded_file(ROOT / "catalog.json").decode())
    if not isinstance(catalog, dict) or set(catalog) != set(ASSETS):
        raise safety.Blocked("BLOCKED: invalid web asset inventory")
    if {p.name for p in ROOT.iterdir()} != set(ASSETS) | {"catalog.json"}:
        raise safety.Blocked("BLOCKED: unexpected web asset")
    files = []
    for name, output in ASSETS.items():
        data = bounded_file(ROOT / name, 1_000_000)
        if digest(data) != catalog[name]:
            raise safety.Blocked("BLOCKED: changed web asset")
        files.append({"path": output, "content": data.decode("utf-8")})
    return files


def render(document):
    document = schema(document)
    files = load_assets()
    domain, models = domain_files(document)
    sql, metadata = backend_files(document)
    files += [
        {"path": path, "content": content}
        for path, content in (
            ("src/generated/domain.ts", domain),
            ("src/generated/models.ts", models),
            ("backend/hasura/schema.sql", sql),
            ("backend/hasura/metadata.json", metadata),
            ("domain.json", encode(document)),
            (
                "next-env.d.ts",
                '/// <reference types="next" />\n'
                '/// <reference types="next/image-types/global" />\n',
            ),
        )
    ]
    for resource in document["resources"]:
        name = resource["name"]
        for path, content in (
            (
                f"src/app/{name}/page.tsx",
                'import { ResourceList } from "../../components/resource";\n'
                "export default function Page() { "
                f'return <ResourceList resource="{name}" />; }}\n',
            ),
            (
                f"src/app/{name}/create/page.tsx",
                'import { ResourceCreate } from "../../../components/resource";\n'
                "export default function Page() { "
                f'return <ResourceCreate resource="{name}" />; }}\n',
            ),
            (
                f"src/app/{name}/[id]/edit/page.tsx",
                'import { ResourceEdit } from "../../../../components/resource";\n'
                "export default async function Page({ params }: "
                "{ params: Promise<{ id: string }> }) { const { id } = await params; "
                f'return <ResourceEdit resource="{name}" id={{id}} />; }}\n',
            ),
        ):
            files.append({"path": path, "content": content})
    safety.validate_manifest(files)
    return files


def inspect(document):
    files = render(document)
    return {
        "status": "PLANNED_LOCAL",
        "router": "NEXT_APP_ROUTER",
        "schema_sha256": digest(encode(schema(document)).encode()),
        "files": {f["path"]: digest(f["content"].encode()) for f in files},
        "backend_connectivity": "NOT_RUN",
        "target_execution": "DISABLED",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }


def write_project(destination, document):
    return safety.write_new_tree(destination, render(document))


FIXTURE_SCHEMA: dict[str, Any] = {
    "schema_version": 1,
    "name": "taskboard",
    "authentication": AUTH,
    "resources": [
        {
            "name": "tasks",
            "label": "Tasks",
            "fields": [
                {"name": "title", "label": "Title", "type": "string", "nullable": False},
                {"name": "done", "label": "Done", "type": "boolean", "nullable": False},
                {"name": "notes", "label": "Notes", "type": "string", "nullable": True},
            ],
        }
    ],
}
