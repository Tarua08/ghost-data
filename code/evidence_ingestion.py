"""Evidence ingestion for the Ghost Data Still Exists audit agent.

The parser converts heterogeneous participant-facing evidence into a common fact
shape while preserving provenance and time. It does not decide deletion status.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shlex
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


TIMESTAMP_KEYS = (
    "observed_at",
    "updated_at",
    "event_at",
    "recorded_at",
    "timestamp",
    "created_at",
    "captured_at",
    "exported_at",
)
SYSTEM_BY_TABLE = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}
SYSTEM_HINTS = {
    "account_service",
    "analytics_platform",
    "backup_service",
    "export_service",
    "identity_service",
    "integration_service",
    "search_service",
    "security_service",
    "support_platform",
}


def parse_timestamp(value: str | None) -> str | None:
    """Validate and canonicalize an ISO-8601 timestamp as UTC text."""
    if not value:
        return None
    candidate = str(value).strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return str(value)


@dataclass(frozen=True)
class ManifestEntry:
    evidence_id: str
    path: Path
    relative_path: str
    origin: str
    captured_at: str


@dataclass
class EvidenceFact:
    evidence_id: str
    file_path: str
    origin: str
    captured_at: str
    source_format: str
    locator: str
    record_type: str
    system_id: str = ""
    resource_id: str = ""
    event_at: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_safe(asdict(self))


@dataclass
class EvidenceDocument:
    entry: ManifestEntry
    sha256: str
    byte_size: int
    facts: list[EvidenceFact]
    warnings: list[str] = field(default_factory=list)


def load_manifest(dataset_dir: Path) -> list[ManifestEntry]:
    """Load the manifest and enforce path confinement and uniqueness."""
    dataset_dir = dataset_dir.resolve()
    manifest_path = dataset_dir / "evidence_files.csv"
    entries: list[ManifestEntry] = []
    seen_ids: set[str] = set()
    seen_paths: set[Path] = set()
    with manifest_path.open(newline="", encoding="utf-8-sig") as handle:
        for row_no, row in enumerate(csv.DictReader(handle), start=2):
            evidence_id = (row.get("file_id") or "").strip()
            relative_path = (row.get("file_path") or "").strip()
            captured_at = parse_timestamp(row.get("captured_at"))
            if not evidence_id or not relative_path or not captured_at:
                raise ValueError(f"Invalid manifest row {row_no}")
            path = (dataset_dir / relative_path).resolve()
            if not path.is_relative_to(dataset_dir):
                raise ValueError(f"Evidence path escapes dataset: {relative_path}")
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Evidence path is missing or unsafe: {relative_path}")
            if evidence_id in seen_ids or path in seen_paths:
                raise ValueError(f"Duplicate manifest entry at row {row_no}")
            seen_ids.add(evidence_id)
            seen_paths.add(path)
            entries.append(
                ManifestEntry(
                    evidence_id=evidence_id,
                    path=path,
                    relative_path=relative_path,
                    origin=(row.get("origin") or "").strip(),
                    captured_at=captured_at,
                )
            )
    return entries


def _fact(
    entry: ManifestEntry,
    source_format: str,
    locator: str,
    record_type: str,
    fields: dict[str, Any],
    system_id: str = "",
) -> EvidenceFact:
    event_at = next(
        (parse_timestamp(fields.get(key)) for key in TIMESTAMP_KEYS if fields.get(key)),
        None,
    )
    resource_id = str(fields.get("resource_id") or "")
    return EvidenceFact(
        evidence_id=entry.evidence_id,
        file_path=entry.relative_path,
        origin=entry.origin,
        captured_at=entry.captured_at,
        source_format=source_format,
        locator=locator,
        record_type=record_type,
        system_id=system_id or str(fields.get("system_id") or fields.get("service") or ""),
        resource_id=resource_id,
        event_at=event_at,
        fields=json_safe(fields),
    )


def _infer_json_system(path_parts: tuple[str, ...], record: dict[str, Any]) -> str:
    explicit = (
        record.get("system_id")
        or record.get("system")
        or record.get("data_store")
        or record.get("service")
    )
    if explicit:
        return str(explicit)
    return next((part for part in reversed(path_parts) if part in SYSTEM_HINTS), "")


def parse_json(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    payload = json.loads(entry.path.read_text(encoding="utf-8"))
    facts: list[EvidenceFact] = []

    def walk(value: Any, parts: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            if "resource_id" in value:
                facts.append(
                    _fact(
                        entry,
                        "json",
                        "$" + "".join(f"[{part}]" if part.isdigit() else f".{part}" for part in parts),
                        str(value.get("record_type") or "")
                        or (
                            parts[-2]
                            if len(parts) > 1 and parts[-1].isdigit()
                            else (parts[-1] if parts else "record")
                        ),
                        value,
                        _infer_json_system(parts, value),
                    )
                )
            for key, item in value.items():
                walk(item, parts + (str(key),))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, parts + (str(index),))

    walk(payload, ())
    if not facts:
        top = payload if isinstance(payload, dict) else {"value": payload}
        facts.append(_fact(entry, "json", "$", "document", top))
    return facts, []


def _sqlite_authorizer(action: int, _arg1: str, _arg2: str, _db: str, _trigger: str) -> int:
    denied = {
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_CREATE_VTABLE,
        sqlite3.SQLITE_DROP_VTABLE,
    }
    return sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK


def parse_sql(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    script = entry.path.read_text(encoding="utf-8")
    if len(script.encode("utf-8")) > 20_000_000:
        raise ValueError("SQL evidence exceeds the 20 MB safety limit")
    connection = sqlite3.connect(":memory:")
    disable_extensions = getattr(connection, "enable_load_extension", None)
    if callable(disable_extensions):
        disable_extensions(False)
    connection.set_authorizer(_sqlite_authorizer)
    instruction_count = 0

    def progress() -> int:
        nonlocal instruction_count
        instruction_count += 1
        return 1 if instruction_count > 1_000_000 else 0

    connection.set_progress_handler(progress, 1000)
    try:
        connection.executescript(script)
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        facts: list[EvidenceFact] = []
        for table in tables:
            quoted_table = '"' + table.replace('"', '""') + '"'
            cursor = connection.execute(f"SELECT * FROM {quoted_table}")
            columns = [item[0] for item in cursor.description]
            for row_no, row in enumerate(cursor, start=1):
                fields = dict(zip(columns, row))
                system_id = SYSTEM_BY_TABLE.get(table, "")
                if table == "snapshot_scope":
                    system_id = str(fields.get("origin_system") or "")
                facts.append(
                    _fact(entry, "sql", f"table={table};row={row_no}", table, fields, system_id)
                )
        return facts, []
    finally:
        connection.close()


LOG_TS_RE = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(?P<body>.*)$")
BRACKET_LOG_RE = re.compile(
    r"^\[(?P<level>[^]]+)\]\s+\[(?P<service>[^]]+)\]\s+"
    r"\[(?P<trace_id>[^]]+)\]\s+(?P<event>[^:]+):\s*(?P<details>.*)$"
)
SYSLOG_RE = re.compile(
    r"^<\d+>\d+\s+\S+\s+(?P<service>\S+)\s+(?P<trace_id>\S+)\s+-\s+-\s+(?P<details>.*)$"
)


def _merge_logfmt(fields: dict[str, Any], body: str) -> None:
    for token in shlex.split(body):
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value


def parse_log(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    facts: list[EvidenceFact] = []
    warnings: list[str] = []
    for line_no, raw_line in enumerate(entry.path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        match = LOG_TS_RE.match(line)
        if not match:
            warnings.append(f"line {line_no}: unrecognized log line")
            continue
        fields: dict[str, Any] = {"timestamp": match.group("timestamp")}
        body = match.group("body")
        try:
            if body.startswith("{"):
                parsed = json.loads(body)
                if not isinstance(parsed, dict):
                    raise ValueError("JSON log body is not an object")
                fields.update(parsed)
                nested = fields.get("message")
                if isinstance(nested, str):
                    _merge_logfmt(fields, nested)
            elif " | " in body:
                parts = [part.strip() for part in body.split(" | ", 4)]
                if len(parts) != 5:
                    raise ValueError("invalid pipe-delimited log body")
                fields.update(
                    {
                        "level": parts[0],
                        "service": parts[1],
                        "trace_id": parts[2],
                        "event": parts[3],
                    }
                )
                _merge_logfmt(fields, parts[4])
            else:
                bracket = BRACKET_LOG_RE.match(body)
                syslog = SYSLOG_RE.match(body)
                if syslog:
                    fields.update(syslog.groupdict())
                    details = str(fields.pop("details", ""))
                    _merge_logfmt(fields, details)
                elif bracket:
                    fields.update(bracket.groupdict())
                    details = str(fields.pop("details", ""))
                    _merge_logfmt(fields, details)
                else:
                    _merge_logfmt(fields, body)
            nested_message = fields.get("message")
            if isinstance(nested_message, str) and "=" in nested_message:
                _merge_logfmt(fields, nested_message)
            if fields.get("requestId") and not fields.get("trace_id"):
                fields["trace_id"] = fields["requestId"]
            facts.append(
                _fact(
                    entry,
                    "log",
                    f"line={line_no}",
                    str(fields.get("event") or "log_event"),
                    fields,
                    str(fields.get("service") or fields.get("function") or ""),
                )
            )
        except (ValueError, json.JSONDecodeError) as exc:
            warnings.append(f"line {line_no}: {exc}")
    return facts, warnings


def parse_text(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    facts: list[EvidenceFact] = []
    for line_no, raw_line in enumerate(entry.path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.strip().removeprefix("- ")
        parts = [part.strip() for part in line.split("|")]
        if len(parts) >= 6 and parse_timestamp(parts[0]):
            fields = {
                "observed_at": parts[0],
                "system_id": parts[1],
                "resource_id": parts[2],
                "category": parts[3],
                "state": parts[4],
                "subject_value": " | ".join(parts[5:]),
            }
            facts.append(
                _fact(entry, "text", f"line={line_no}", parts[3], fields, parts[1])
            )
    if not facts:
        facts.append(
            _fact(
                entry,
                "text",
                "document",
                "text_document",
                {"text": entry.path.read_text(encoding="utf-8", errors="replace")},
            )
        )
    return facts, []


def parse_pdf(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    from pypdf import PdfReader

    facts: list[EvidenceFact] = []
    warnings: list[str] = []
    reader = PdfReader(str(entry.path))
    pages: list[str] = []
    for page_no, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        pages.append(text)
        if not text.strip():
            warnings.append(f"page {page_no}: no extractable text; VLM/OCR required")
        facts.append(
            _fact(
                entry,
                "pdf",
                f"page={page_no}",
                "pdf_page",
                {"page": page_no, "text": text},
            )
        )
    full_text = "\n".join(pages)
    resource_ids = sorted(set(re.findall(r"\b(?:account|analytics|audit_record|backup|data_flow|export|search|support|tombstone)_\d+\b", full_text)))
    record_type = "SUPPORT_ATTACHMENT" if "attachment" in full_text.casefold() else "pdf_record"
    for resource_id in resource_ids:
        facts.append(
            _fact(
                entry,
                "pdf",
                f"document;resource={resource_id}",
                record_type,
                {"resource_id": resource_id, "text": full_text},
                entry.origin if entry.origin in SYSTEM_HINTS else "",
            )
        )
    return facts, warnings


def parse_image(entry: ManifestEntry) -> tuple[list[EvidenceFact], list[str]]:
    from PIL import Image

    with Image.open(entry.path) as image:
        fields = {
            "width": image.width,
            "height": image.height,
            "mode": image.mode,
            "image_format": image.format,
            "requires_vlm_extraction": True,
        }
    facts = [_fact(entry, "image", "image", "image_artifact", fields)]
    repo_root = entry.path.parents[3]
    cache_dir = repo_root / ".cache" / "visual"
    digest = hashlib.sha256(entry.path.read_bytes()).hexdigest()
    candidates = sorted(cache_dir.glob(f"{entry.evidence_id}-{digest}-*.json"))
    if not candidates:
        return facts, ["visual content requires VLM extraction before decision use"]

    envelope = json.loads(candidates[-1].read_text(encoding="utf-8"))
    extraction = envelope.get("extraction", {})
    for index, record in enumerate(extraction.get("records", []), start=1):
        record_fields: dict[str, Any] = {
            "observed_at": record.get("observed_at", ""),
            "state": record.get("state", ""),
            "visible_text": record.get("visible_text", ""),
        }
        for item in record.get("identifiers", []):
            record_fields[str(item.get("type", "identifier"))] = item.get("value", "")
        for item in record.get("attributes", []):
            record_fields[str(item.get("name", "attribute"))] = item.get("value", "")
        record_fields["resource_id"] = record.get("resource_id", "")
        facts.append(
            _fact(
                entry,
                "image",
                f"visual_record={index};region={record.get('region', '')}",
                record.get("record_type", "visual_record") or "visual_record",
                record_fields,
                record.get("system_id", ""),
            )
        )
    facts[0].fields["requires_vlm_extraction"] = False
    return facts, []


PARSERS = {
    ".json": parse_json,
    ".sql": parse_sql,
    ".log": parse_log,
    ".txt": parse_text,
    ".pdf": parse_pdf,
    ".png": parse_image,
    ".jpg": parse_image,
    ".jpeg": parse_image,
}


def ingest_entry(entry: ManifestEntry) -> EvidenceDocument:
    suffix = entry.path.suffix.lower()
    parser = PARSERS.get(suffix)
    if parser is None:
        raise ValueError(f"Unsupported evidence format: {suffix}")
    raw = entry.path.read_bytes()
    facts, warnings = parser(entry)
    return EvidenceDocument(
        entry=entry,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
        facts=facts,
        warnings=warnings,
    )


def ingest_dataset(dataset_dir: Path) -> list[EvidenceDocument]:
    return [ingest_entry(entry) for entry in load_manifest(dataset_dir)]


def iter_facts(documents: Iterable[EvidenceDocument]) -> Iterator[EvidenceFact]:
    for document in documents:
        yield from document.facts


def write_index(documents: list[EvidenceDocument], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for fact in iter_facts(documents):
            handle.write(json.dumps(fact.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(destination)


def build_summary(documents: list[EvidenceDocument]) -> dict[str, Any]:
    format_counts: dict[str, int] = {}
    fact_counts: dict[str, int] = {}
    warning_count = 0
    for document in documents:
        suffix = document.entry.path.suffix.lower().removeprefix(".")
        format_counts[suffix] = format_counts.get(suffix, 0) + 1
        warning_count += len(document.warnings)
        for fact in document.facts:
            fact_counts[fact.source_format] = fact_counts.get(fact.source_format, 0) + 1
    return {
        "documents": len(documents),
        "facts": sum(fact_counts.values()),
        "documents_by_format": dict(sorted(format_counts.items())),
        "facts_by_format": dict(sorted(fact_counts.items())),
        "warnings": warning_count,
    }
