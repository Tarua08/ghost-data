"""Bounded Gemini extraction for participant-facing screenshot evidence."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from google import genai
from google.genai import types

from evidence_ingestion import ManifestEntry, load_manifest


PROMPT_VERSION = "visual-evidence-v1"
SUPPORTED_IMAGES = {".png", ".jpg", ".jpeg"}
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "document_text": {"type": "string"},
        "records": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "system_id": {"type": "string"},
                    "resource_id": {"type": "string"},
                    "record_type": {"type": "string"},
                    "observed_at": {"type": "string"},
                    "state": {"type": "string"},
                    "identifiers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string"},
                                "value": {"type": "string"},
                            },
                            "required": ["type", "value"],
                        },
                    },
                    "attributes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"},
                            },
                            "required": ["name", "value"],
                        },
                    },
                    "visible_text": {"type": "string"},
                    "region": {"type": "string"},
                },
                "required": [
                    "system_id",
                    "resource_id",
                    "record_type",
                    "observed_at",
                    "state",
                    "identifiers",
                    "attributes",
                    "visible_text",
                    "region",
                ],
            },
        },
    },
    "required": ["document_text", "records"],
}

EXTRACTION_PROMPT = """You extract facts from a screenshot used as audit evidence.

Rules:
- Report only text and state visibly supported by the image.
- Do not decide whether deletion is complete and do not recommend remediation.
- Do not infer missing identifiers, timestamps, systems, or state.
- Preserve exact spelling, capitalization, punctuation, hashes, email addresses,
  phone numbers, user IDs, resource IDs, and timestamps.
- Create one record per visibly distinct resource or row.
- Use an empty string when a scalar field is not visible.
- `region` must briefly locate the item, for example `row 3` or `details panel`.
- `visible_text` must be the shortest verbatim text that supports the record.
- Put identifiers such as email, phone, email_hash, user_id, customer_reference,
  and subject_reference in `identifiers`.
- Put other visible key/value properties in `attributes`.
- `document_text` is a concise transcription of headings and relevant rows.
"""


@dataclass
class UsageTotals:
    calls: int = 0
    prompt_tokens: int = 0
    candidate_tokens: int = 0
    total_tokens: int = 0
    cached_files: int = 0


def load_local_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def image_cache_path(cache_dir: Path, entry: ManifestEntry, model: str) -> Path:
    digest = hashlib.sha256(entry.path.read_bytes()).hexdigest()
    model_slug = model.replace("/", "_")
    return cache_dir / f"{entry.evidence_id}-{digest}-{model_slug}-{PROMPT_VERSION}.json"


def _validate_result(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("records"), list):
        raise ValueError("visual response is not a records object")
    if not isinstance(payload.get("document_text"), str):
        raise ValueError("visual response lacks document_text")
    required = set(RESPONSE_SCHEMA["properties"]["records"]["items"]["required"])
    for index, record in enumerate(payload["records"]):
        if not isinstance(record, dict) or set(record) != required:
            raise ValueError(f"visual record {index} has invalid fields")
        if not isinstance(record["identifiers"], list) or not isinstance(record["attributes"], list):
            raise ValueError(f"visual record {index} has invalid lists")
    return payload


def _usage_dict(metadata: Any) -> dict[str, int]:
    return {
        "prompt_tokens": int(getattr(metadata, "prompt_token_count", 0) or 0),
        "candidate_tokens": int(getattr(metadata, "candidates_token_count", 0) or 0),
        "total_tokens": int(getattr(metadata, "total_token_count", 0) or 0),
    }


def extract_image(
    client: genai.Client,
    entry: ManifestEntry,
    model: str,
    cache_dir: Path,
    force: bool = False,
) -> tuple[dict[str, Any], bool]:
    destination = image_cache_path(cache_dir, entry, model)
    if destination.is_file() and not force:
        return json.loads(destination.read_text(encoding="utf-8")), True

    mime_type = "image/jpeg" if entry.path.suffix.lower() in {".jpg", ".jpeg"} else "image/png"
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=model,
                contents=[
                    EXTRACTION_PROMPT,
                    types.Part.from_bytes(data=entry.path.read_bytes(), mime_type=mime_type),
                ],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=RESPONSE_SCHEMA,
                ),
            )
            extracted = _validate_result(json.loads(response.text or ""))
            envelope = {
                "evidence_id": entry.evidence_id,
                "file_path": entry.relative_path,
                "image_sha256": hashlib.sha256(entry.path.read_bytes()).hexdigest(),
                "model": model,
                "prompt_version": PROMPT_VERSION,
                "extraction": extracted,
                "usage": _usage_dict(response.usage_metadata),
            }
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.replace(destination)
            return envelope, False
        except Exception as exc:  # bounded retry; caller receives final failure
            last_error = exc
            if attempt < 2:
                time.sleep(2**attempt)
    assert last_error is not None
    raise RuntimeError(f"visual extraction failed for {entry.evidence_id}: {last_error}") from None


def extract_all_images(
    dataset_dir: Path,
    cache_dir: Path,
    env_path: Path,
    force: bool = False,
) -> UsageTotals:
    load_local_env(env_path)
    model = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash").strip()
    entries = [entry for entry in load_manifest(dataset_dir) if entry.path.suffix.lower() in SUPPORTED_IMAGES]
    totals = UsageTotals()

    # A reproduced run may already have every model response in its content-addressed
    # cache. Do not require or initialize credentials unless a network call is needed.
    all_cached = not force and all(image_cache_path(cache_dir, entry, model).is_file() for entry in entries)
    if all_cached:
        for position, entry in enumerate(entries, start=1):
            envelope = json.loads(image_cache_path(cache_dir, entry, model).read_text(encoding="utf-8"))
            totals.cached_files += 1
            print(
                f"[{position}/{len(entries)}] {entry.evidence_id}: "
                f"{len(envelope['extraction']['records'])} records (cached)"
            )
        return totals

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is required because one or more screenshot extractions "
            "are missing from the cache"
        )
    client = genai.Client(api_key=api_key)
    try:
        for position, entry in enumerate(entries, start=1):
            envelope, cached = extract_image(client, entry, model, cache_dir, force=force)
            if cached:
                totals.cached_files += 1
            else:
                totals.calls += 1
                usage = envelope["usage"]
                totals.prompt_tokens += usage["prompt_tokens"]
                totals.candidate_tokens += usage["candidate_tokens"]
                totals.total_tokens += usage["total_tokens"]
            print(
                f"[{position}/{len(entries)}] {entry.evidence_id}: "
                f"{len(envelope['extraction']['records'])} records"
                + (" (cached)" if cached else "")
            )
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    return totals

