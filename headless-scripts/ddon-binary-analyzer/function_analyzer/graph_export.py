"""Deterministic Ghidra API export for executable call-graph evidence.

This module intentionally consumes Ghidra ``Function`` APIs rather than
decompiled C text.  It emits direct calls and signature-level type usage.  It
does not claim stream reads or field writes because those require a separate,
verified Pcode data-flow pass.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FunctionGraphRecord:
    """Portable representation of a Ghidra function and its direct calls."""

    qualified_name: str
    address: str
    signature: str
    address_start: str
    address_end: str
    type_names: tuple[str, ...]
    calls: tuple[str, ...]
    unresolved_type_names: tuple[str, ...] = ()


class FunctionGraphExporter:
    """Collect and write evidence-backed function graph bundles."""

    SCHEMA_VERSION = "1.0"
    PRODUCER = "ddon-binary-analyzer"

    def collect(self, analyzer: Any, function_name: str, max_depth: int) -> list[FunctionGraphRecord]:
        """Collect a breadth-first graph using Ghidra's direct-call API.

        Args:
            analyzer: Initialized ``FunctionDecompilationAnalyzer`` instance.
            function_name: Qualified root function name.
            max_depth: Maximum direct-call traversal depth.

        Returns:
            Deterministically sorted records keyed by entry-point address.

        Raises:
            ValueError: If the root function cannot be found.
        """
        root = analyzer.function_search.find_function_by_name(function_name)
        if root is None:
            raise ValueError(f"Function '{function_name}' not found")

        queue: deque[tuple[Any, str, int]] = deque([(root, function_name, 0)])
        visited: set[str] = set()
        records: list[FunctionGraphRecord] = []
        while queue:
            function, qualified_name, depth = queue.popleft()
            address = str(function.getEntryPoint())
            if address in visited:
                continue
            visited.add(address)

            direct_calls = analyzer.cross_ref_analyzer.analyze_related_functions(function).get(
                "direct_calls", []
            )
            call_names = tuple(
                sorted(
                    analyzer.function_search.get_qualified_function_name(called)
                    for called in direct_calls
                )
            )
            records.append(self._record(function, qualified_name, call_names))
            if depth < max_depth:
                for called in direct_calls:
                    queue.append(
                        (
                            called,
                            analyzer.function_search.get_qualified_function_name(called),
                            depth + 1,
                        )
                    )
        return sorted(records, key=lambda record: (record.address, record.qualified_name))

    def write(
        self,
        records: list[FunctionGraphRecord],
        output_dir: Path,
        build_id: str,
        root_function: str,
        source_artifact_path: Path | None = None,
    ) -> Path:
        """Write function nodes, direct-call edges, and a source manifest.

        Args:
            records: Records collected from Ghidra APIs.
            output_dir: Destination directory for the JSONL bundle.
            build_id: Client build identifier associated with the Ghidra program.
            root_function: Root function used to create the traversal.
            source_artifact_path: Optional path to the analyzed binary used by Ghidra.

        Returns:
            Path to the generated manifest file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        source_id = f"source:{build_id}:ghidra:{self._safe_id(root_function)}"
        source_properties: dict[str, Any] = {
            "format": "Ghidra API function graph",
            "root_function": root_function,
            "source_revision": build_id,
            "deterministic": True,
        }
        source_artifacts: list[dict[str, str]] = []
        source_artifact_warnings: list[str] = []
        if source_artifact_path is not None and source_artifact_path.exists():
            source_properties["path"] = str(source_artifact_path)
            source_properties["sha256"] = self._sha256_file(source_artifact_path)
            source_artifacts.append(
                {
                    "id": source_id,
                    "path": str(source_artifact_path),
                    "sha256": str(source_properties["sha256"]),
                    "format": "binary/program",
                }
            )
        else:
            source_artifact_warnings.append(
                "Analyzed program path was unavailable; source_artifact coverage is partial"
            )
        nodes: list[dict[str, Any]] = [
            self._node(source_id, "SourceArtifact", source_properties)
        ]
        relationships: list[dict[str, Any]] = []
        skipped_calls: list[dict[str, str]] = []
        unresolved_signature_types: list[dict[str, str]] = []
        ids_by_name: dict[str, str] = {}
        for record in records:
            function_id = self._function_id(build_id, record.address)
            ids_by_name[record.qualified_name] = function_id
            evidence_id = f"evidence:ghidra:{build_id}:{self._safe_id(record.address)}"
            nodes.extend(
                [
                    self._node(
                        function_id,
                        "Function",
                        {
                            "qualified_name": record.qualified_name,
                            "name": record.qualified_name.rsplit("::", 1)[-1],
                            "owner_name": (
                                record.qualified_name.rsplit("::", 1)[0]
                                if "::" in record.qualified_name
                                else ""
                            ),
                            "address": record.address,
                            "producer": self.PRODUCER,
                            "signature": record.signature,
                            "source_revision": build_id,
                            "deterministic": True,
                        },
                    ),
                    self._node(
                        evidence_id,
                        "Evidence",
                        {
                            "kind": "ghidra-function-range",
                            "address_start": record.address_start,
                            "address_end": record.address_end,
                            "producer": self.PRODUCER,
                            "source_revision": build_id,
                            "deterministic": True,
                        },
                    ),
                ]
            )
            relationships.extend(
                [
                    self._relationship(function_id, "EVIDENCED_BY", evidence_id),
                    self._relationship(evidence_id, "DERIVED_FROM", source_id),
                ]
            )
            for type_name in record.type_names:
                logical_type_id = f"logical-type:{type_name}"
                nodes.append(self._node(logical_type_id, "LogicalType", {"name": type_name}))
                relationships.append(self._relationship(function_id, "USES_TYPE", logical_type_id))
            for type_name in record.unresolved_type_names:
                unresolved_signature_types.append(
                    {"function": record.qualified_name, "type_name": type_name}
                )

        for record in records:
            source_function_id = ids_by_name[record.qualified_name]
            for call_name in record.calls:
                target_function_id = ids_by_name.get(call_name)
                if target_function_id:
                    relationships.append(self._relationship(source_function_id, "CALLS", target_function_id))
                else:
                    skipped_calls.append(
                        {"source_function": record.qualified_name, "target_function": call_name}
                    )

        nodes_path = output_dir / "nodes.jsonl"
        relationships_path = output_dir / "relationships.jsonl"
        self._write_jsonl(nodes_path, self._deduplicate(nodes, "id"))
        self._write_jsonl(relationships_path, self._deduplicate_relationships(relationships))
        manifest = {
            "schema_version": self.SCHEMA_VERSION,
            "producer": self.PRODUCER,
            "build_id": build_id,
            "root_function": root_function,
            "source_revision": build_id,
            "source_artifacts": source_artifacts,
            "warnings": {
                "source_artifacts": source_artifact_warnings,
                "skipped_calls": skipped_calls,
                "unresolved_signature_types": unresolved_signature_types,
            },
            "files": {
                "nodes": self._descriptor(nodes_path),
                "relationships": self._descriptor(relationships_path),
            },
        }
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest_path

    def _record(
        self, function: Any, qualified_name: str, calls: tuple[str, ...]
    ) -> FunctionGraphRecord:
        """Convert a Ghidra function into a portable graph record."""
        signature = function.getPrototypeString(False, False)
        address = str(function.getEntryPoint())
        body = function.getBody()
        type_names, unresolved_type_names = self._signature_type_summary(function)
        return FunctionGraphRecord(
            qualified_name=qualified_name,
            address=address,
            signature=signature,
            address_start=str(body.getMinAddress()),
            address_end=str(body.getMaxAddress()),
            type_names=type_names,
            unresolved_type_names=unresolved_type_names,
            calls=calls,
        )

    @staticmethod
    def _signature_type_summary(function: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Extract resolved and unresolved signature type names without decompilation."""
        raw_type_names = {str(function.getReturnType())}
        for parameter in function.getParameters():
            raw_type_names.add(str(parameter.getDataType()))
        resolved = tuple(sorted(type_name for type_name in raw_type_names if type_name and type_name != "undefined"))
        unresolved = tuple(sorted(type_name for type_name in raw_type_names if type_name == "undefined"))
        return resolved, unresolved

    @staticmethod
    def _node(node_id: str, kind: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create a graph node record."""
        return {"id": node_id, "kind": kind, "properties": properties}

    @staticmethod
    def _relationship(source_id: str, rel_type: str, target_id: str) -> dict[str, Any]:
        """Create a graph relationship record."""
        return {"source_id": source_id, "type": rel_type, "target_id": target_id, "properties": {}}

    @staticmethod
    def _function_id(build_id: str, address: str) -> str:
        """Return a stable source-scoped Ghidra function ID."""
        return f"function:{build_id}:{FunctionGraphExporter._safe_id(address)}"

    @staticmethod
    def _safe_id(value: str) -> str:
        """Return a stable short digest for an address or qualified name."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
        """Write stable JSONL records."""
        path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8"
        )

    @staticmethod
    def _descriptor(path: Path) -> dict[str, str]:
        """Return the manifest descriptor for an output file."""
        return {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    @staticmethod
    def _sha256_file(path: Path) -> str:
        """Return the SHA-256 digest of a file without loading it into memory."""
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _deduplicate(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        """Deduplicate same-ID nodes while rejecting property disagreements."""
        result: dict[str, dict[str, Any]] = {}
        for record in records:
            existing = result.get(record[key])
            if existing is not None and existing != record:
                raise ValueError(f"Conflicting graph node export for {record[key]}")
            result[record[key]] = record
        return [result[record_id] for record_id in sorted(result)]

    @staticmethod
    def _deduplicate_relationships(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate relationships by their complete stable representation."""
        unique = {json.dumps(record, sort_keys=True): record for record in records}
        return [unique[key] for key in sorted(unique)]
