#!/usr/bin/env python3
"""Reconcile exact pnpm pins, package snapshots and a retained pnpm graph."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import yaml


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate mapping keys instead of silently replacing them."""


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError("Duplicate YAML key")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def package_key(name, version):
    return name + "@" + version


def base_key(snapshot):
    return snapshot.split("(", 1)[0]


def inspect_lock(document):
    require(document["lockfileVersion"] == "9.0", "Lockfile format changed")
    packages = document["packages"]
    snapshots = document["snapshots"]
    for name, entry in packages.items():
        resolution = entry["resolution"]
        require(set(resolution) == {"integrity"}, "Nonregistry resolution")
        integrity = resolution["integrity"]
        require(integrity.startswith("sha512-"), "Expected SHA-512 pin")
        raw = base64.b64decode(integrity[7:], validate=True)
        require(len(raw) == 64, "Invalid SHA-512 integrity length")
        require(any(base_key(key) == name for key in snapshots),
                "Package lacks a dependency snapshot")
    edges = 0
    for key, entry in snapshots.items():
        require(base_key(key) in packages, "Snapshot lacks package pin")
        for kind in ("dependencies", "optionalDependencies"):
            for name, version in entry.get(kind, {}).items():
                require(package_key(name, version) in snapshots,
                        "Dependency does not resolve to exact snapshot")
                edges += 1
    return {"packages": len(packages), "snapshots": len(snapshots),
            "dependencyEdges": edges}


def inspect_graph(graph, packages, direct):
    seen = set()
    physical = set()

    def visit(entries):
        for name, entry in entries.items():
            key = package_key(name, entry["version"])
            require(key in packages, "Graph node missing from locked packages")
            expected = "https://registry.npmjs.org/"
            require(entry["resolved"].startswith(expected),
                    "Graph resolution outside default registry")
            seen.add(key)
            if (Path(entry["path"]) / "package.json").is_file():
                physical.add(key)
            for kind in ("dependencies", "optionalDependencies"):
                visit(entry.get(kind, {}))

    require(len(graph) == 1 and graph[0]["private"] is True,
            "Expected one private tooling graph")
    require(set(graph[0]["devDependencies"]) == set(direct),
            "Direct graph dependency set mismatch")
    for name, pin in direct.items():
        require(graph[0]["devDependencies"][name]["version"] ==
                base_key(pin["version"]), "Direct graph version mismatch")
    visit(graph[0]["devDependencies"])
    return {"listedUniquePackages": len(seen),
            "withPresentPackageManifest": len(physical),
            "note": "A listed optional node is not runtime acceptance."}


def inspect_direct(project, direct):
    for name, pin in direct.items():
        key = package_key(name, pin["version"])
        require(key in project["snapshots"] and
                base_key(key) in project["packages"],
                "Direct importer lacks an exact package/snapshot")


def controls(project, direct, graph):
    def refused(work, expected):
        try:
            work()
        except ValueError as error:
            require(str(error) == expected, "Wrong refusal control")
            return
        raise RuntimeError("Dependency control accepted invalid evidence")

    name = next(iter(direct))
    missing = copy.deepcopy(graph)
    del missing[0]["devDependencies"][name]
    refused(lambda: inspect_graph(missing, project["packages"], direct),
            "Direct graph dependency set mismatch")
    wrong = copy.deepcopy(graph)
    wrong[0]["devDependencies"][name]["version"] = "0.0.0"
    refused(lambda: inspect_graph(wrong, project["packages"], direct),
            "Direct graph version mismatch")
    key = package_key(name, direct[name]["version"])
    for collection, removed in (("snapshots", key),
                                ("packages", base_key(key))):
        damaged = copy.deepcopy(project)
        del damaged[collection][removed]
        refused(lambda: inspect_direct(damaged, direct),
                "Direct importer lacks an exact package/snapshot")
    empty = {"packages": {}, "snapshots": {}}
    refused(lambda: inspect_direct(empty, direct),
            "Direct importer lacks an exact package/snapshot")
    damaged = copy.deepcopy(project)
    damaged["snapshots"][key]["dependencies"] = {"missing": "0.0.0"}
    refused(lambda: inspect_lock(damaged),
            "Dependency does not resolve to exact snapshot")
    damaged = copy.deepcopy(project)
    damaged["packages"][base_key(key)]["resolution"] = {"tarball": "x"}
    refused(lambda: inspect_lock(damaged), "Nonregistry resolution")
    refused(lambda: yaml.load("a: 1\na: 2\n", Loader=UniqueLoader),
            "Duplicate YAML key")
    damaged["packages"][base_key(key)]["resolution"] = {
        "integrity": "sha512-YQ==",
    }
    refused(lambda: inspect_lock(damaged), "Invalid SHA-512 integrity length")
    print("PASS: nine independent dependency evidence refusal controls")


def main():
    require(len(sys.argv) in (2, 3), "Give pnpm JSON and optional --self-test")
    require(len(sys.argv) == 2 or sys.argv[2] == "--self-test",
            "Unknown dependency harness option")
    root = Path(__file__).resolve().parents[3]
    lock = root / "pnpm-lock.yaml"
    documents = list(yaml.load_all(lock.read_text(), Loader=UniqueLoader))
    require(len(documents) == 2, "Expected manager and project lock documents")
    manager, project = documents
    manifest = json.loads((root / "package.json").read_text())
    manager_pin = manager["importers"]["."]["packageManagerDependencies"]
    require(manifest["packageManager"] ==
            "pnpm@" + manager_pin["pnpm"]["version"],
            "Package manager version mismatch")
    direct = project["importers"]["."]["devDependencies"]
    require(set(direct) == set(manifest["devDependencies"]),
            "Direct dependency set mismatch")
    for name, version in manifest["devDependencies"].items():
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version),
                "Direct dependency is not an exact version")
        require(direct[name]["specifier"] == version and
                base_key(direct[name]["version"]) == version,
                "Direct dependency pin mismatch")
    inspect_direct(project, direct)
    graph = json.loads(Path(sys.argv[1]).read_text())
    result = {"manager": inspect_lock(manager),
              "project": inspect_lock(project),
              "graph": inspect_graph(
                  graph, project["packages"], direct),
              "lockSha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
              "yamlVersion": yaml.__version__}
    print(json.dumps(result, indent=2))
    if len(sys.argv) == 3:
        controls(project, direct, graph)


if __name__ == "__main__":
    main()
