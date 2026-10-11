"""Tests for deterministic Ghidra graph export summaries."""

import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, cast


def _load_graph_export_module() -> Any:
    """Load the graph export module without importing Ghidra-only package side effects."""
    module_path = Path(__file__).resolve().parents[1] / "function_analyzer" / "graph_export.py"
    spec = importlib.util.spec_from_file_location("ddon_graph_export", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load graph export module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_GRAPH_EXPORT_MODULE = _load_graph_export_module()
FunctionGraphExporter = cast(Any, _GRAPH_EXPORT_MODULE.FunctionGraphExporter)
FunctionGraphRecord = cast(Any, _GRAPH_EXPORT_MODULE.FunctionGraphRecord)


def test_write_surfaces_skipped_calls_and_unresolved_signature_types(tmp_path: Path) -> None:
    """Manifest warnings describe omitted call edges and unresolved signature types."""
    exporter = FunctionGraphExporter()
    source_binary = tmp_path / "DDOORBIS.elf"
    source_binary.write_bytes(b"ghidra graph export fixture")
    manifest_path = exporter.write(
        [
            FunctionGraphRecord(
                qualified_name="rLayout::load",
                address="00401000",
                signature="bool rLayout::load(rLayout::SetInfo)",
                address_start="00401000",
                address_end="004010FF",
                type_names=("bool", "rLayout::SetInfo"),
                unresolved_type_names=("undefined",),
                calls=("rLayout::helper", "rLayout::missingHelper"),
            ),
            FunctionGraphRecord(
                qualified_name="rLayout::helper",
                address="00401100",
                signature="void rLayout::helper()",
                address_start="00401100",
                address_end="0040118F",
                type_names=("void",),
                calls=(),
            ),
        ],
        tmp_path / "export",
        "ps4-02020005",
        "rLayout::load",
        source_binary,
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    nodes = [
        json.loads(line)
        for line in (manifest_path.parent / "nodes.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    relationships = [
        json.loads(line)
        for line in (manifest_path.parent / "relationships.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert manifest["source_artifacts"] == [
        {
            "format": "binary/program",
            "id": f"source:ps4-02020005:ghidra:{FunctionGraphExporter._safe_id('rLayout::load')}",
            "path": str(source_binary),
            "sha256": FunctionGraphExporter._sha256_file(source_binary),
        }
    ]
    assert manifest["warnings"]["source_artifacts"] == []
    assert manifest["warnings"]["skipped_calls"] == [
        {"source_function": "rLayout::load", "target_function": "rLayout::missingHelper"}
    ]
    assert manifest["warnings"]["unresolved_signature_types"] == [
        {"function": "rLayout::load", "type_name": "undefined"}
    ]
    assert any(
        node["kind"] == "SourceArtifact"
        and node["properties"]["path"] == str(source_binary)
        and node["properties"]["sha256"] == FunctionGraphExporter._sha256_file(source_binary)
        for node in nodes
    )
    assert any(relationship["type"] == "CALLS" for relationship in relationships)
    assert not any(
        relationship["type"] == "CALLS"
        and relationship["target_id"].endswith(FunctionGraphExporter._safe_id("rLayout::missingHelper"))
        for relationship in relationships
    )