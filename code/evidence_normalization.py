"""Normalize evidence facts and construct cutoff-safe per-case contexts."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from evidence_ingestion import EvidenceFact, ingest_dataset, iter_facts, parse_timestamp
from identity_resolution import IdentityResolver, ResolvedIdentity, normalize_identifier


ORIGIN_SYSTEM = {
    "account_admin_portal": "account_service",
    "analytics_platform": "analytics_platform",
    "backup_service": "backup_service",
    "export_service": "export_service",
    "identity_service": "identity_service",
    "integration_admin": "integration_service",
    "marketing_platform": "marketing_platform",
    "object_storage": "object_storage",
    "search_index_admin": "search_service",
    "security_service": "security_service",
    "support_platform": "support_platform",
}
SYSTEM_ALIASES = {
    "bridgeops": "integration_service",
    "customer_directory_v3": "search_service",
    "helpline console": "support_platform",
    "nimbus object storage": "object_storage",
    "northstar shop": "account_service",
    "pulse analytics": "analytics_platform",
    "sentinel": "security_service",
    "vault recovery manager": "backup_service",
}
RESOURCE_FIELD_PRIORITY = (
    "account_id",
    "analytics_id",
    "ticket_id",
    "order_id",
    "resource_id",
)
RESOURCE_SYSTEM_PREFIXES = (
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("legal_hold_", "legal_service"),
    ("tombstone_", "identity_service"),
    ("account_", "account_service"),
    ("analytics_", "analytics_platform"),
    ("backup_", "backup_service"),
    ("export_", "export_service"),
    ("marketing_", "marketing_platform"),
    ("search_", "search_service"),
    ("support_", "support_platform"),
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
USER_ID_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _dt(value: str) -> datetime:
    canonical = parse_timestamp(value)
    if canonical is None:
        raise ValueError(f"Invalid timestamp: {value}")
    return datetime.fromisoformat(canonical.replace("Z", "+00:00"))


def normalize_system(fact: EvidenceFact) -> str:
    explicit = fact.system_id.strip()
    origin_system = ORIGIN_SYSTEM.get(fact.origin)
    if fact.source_format == "image" and origin_system:
        return origin_system
    if explicit in ORIGIN_SYSTEM.values():
        return explicit
    alias = SYSTEM_ALIASES.get(explicit.casefold())
    if alias:
        return alias
    if origin_system:
        return origin_system
    for prefix, system_id in RESOURCE_SYSTEM_PREFIXES:
        if fact.resource_id.startswith(prefix):
            return system_id
    return explicit


def normalize_resource_id(fact: EvidenceFact) -> str:
    resource_id = fact.resource_id.strip()
    for field in RESOURCE_FIELD_PRIORITY:
        candidate = str(fact.fields.get(field) or "").strip()
        if not candidate:
            continue
        if field == "account_id" and not resource_id.startswith("account_"):
            return candidate
        if field == "analytics_id" and not resource_id.startswith("analytics_"):
            return candidate
        if not resource_id:
            return candidate
    return resource_id


def normalize_fact(fact: EvidenceFact) -> EvidenceFact:
    return replace(
        fact,
        system_id=normalize_system(fact),
        resource_id=normalize_resource_id(fact),
    )


def fact_quality(fact: EvidenceFact) -> tuple[int, int, int]:
    nonempty = sum(value not in (None, "", [], {}) for value in fact.fields.values())
    return (nonempty, len(str(fact.fields.get("visible_text") or "")), len(fact.locator))


def deduplicate_facts(facts: Iterable[EvidenceFact]) -> list[EvidenceFact]:
    """Collapse duplicate table/detail views within one evidence artifact."""
    selected: dict[tuple[str, str, str], EvidenceFact] = {}
    unkeyed: list[EvidenceFact] = []
    for raw_fact in facts:
        fact = normalize_fact(raw_fact)
        if not fact.resource_id or fact.record_type == "image_artifact":
            unkeyed.append(fact)
            continue
        key = (fact.evidence_id, fact.system_id, fact.resource_id)
        previous = selected.get(key)
        if previous is None or fact_quality(fact) > fact_quality(previous):
            selected[key] = fact
    return sorted(
        [*selected.values(), *unkeyed],
        key=lambda fact: (
            fact.evidence_id,
            fact.system_id,
            fact.resource_id,
            fact.record_type,
            fact.locator,
        ),
    )


def fact_is_eligible(fact: EvidenceFact, cutoff: str) -> bool:
    cutoff_dt = _dt(cutoff)
    if _dt(fact.captured_at) > cutoff_dt:
        return False
    return fact.event_at is None or _dt(fact.event_at) <= cutoff_dt


def _normalized_scalar_values(value: Any, key: str = "") -> set[str]:
    output: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            output.update(_normalized_scalar_values(child, str(child_key)))
    elif isinstance(value, list):
        for child in value:
            output.update(_normalized_scalar_values(child, key))
    elif value not in (None, ""):
        text = str(value).strip()
        kind = ""
        lowered = key.casefold()
        if "email_hash" in lowered or lowered == "hash":
            kind = "email_hash"
        elif "email" in lowered:
            kind = "email"
        elif "phone" in lowered:
            kind = "phone"
        elif lowered in {"user_id", "subject_reference", "customer_reference"}:
            kind = lowered
        if kind:
            normalized = normalize_identifier(kind, text)
            if normalized:
                output.add(normalized)
        for email in EMAIL_RE.findall(text):
            output.add(normalize_identifier("email", email))
        for user_id in USER_ID_RE.findall(text):
            output.add(normalize_identifier("user_id", user_id))
        for digest in SHA256_RE.findall(text):
            output.add(normalize_identifier("email_hash", digest))
    return output


def fact_matches_identity(fact: EvidenceFact, identity: ResolvedIdentity) -> bool:
    values = _normalized_scalar_values(fact.fields)
    return bool(values & identity.lookup_values)


def _fact_link_values(fact: EvidenceFact, field_name: str) -> set[str]:
    value = fact.fields.get(field_name)
    if value in (None, ""):
        return set()
    return {str(value)}


@dataclass(frozen=True)
class Activity:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


def load_activities(dataset_dir: Path) -> list[Activity]:
    activities: list[Activity] = []
    with (dataset_dir / "system_activity.csv").open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            activities.append(
                Activity(
                    activity_id=row["activity_id"].strip(),
                    event_time=parse_timestamp(row["event_time"]) or "",
                    event_type=row["event_type"].strip(),
                    source_system=row["source_system"].strip(),
                    target_system=row["target_system"].strip(),
                    resource_id=row["resource_id"].strip(),
                    reported_result=row["reported_result"].strip(),
                    details=row["details"].strip(),
                )
            )
    return activities


def build_case_context(
    request: dict[str, str],
    resolver: IdentityResolver,
    facts: list[EvidenceFact],
    activities: list[Activity],
) -> dict[str, Any]:
    cutoff = request["audit_at"]
    identity = resolver.resolve(request["email"], cutoff)
    eligible = [fact for fact in facts if fact_is_eligible(fact, cutoff)]
    matched = [fact for fact in eligible if fact_matches_identity(fact, identity)]

    # Log evidence often puts the lookup identifier on one line and the resulting
    # resource on another. A shared trace_id is an exact, source-provided join.
    trace_ids = {
        trace_id
        for fact in matched
        for trace_id in _fact_link_values(fact, "trace_id")
    }
    if trace_ids:
        existing = {(fact.evidence_id, fact.locator) for fact in matched}
        for fact in eligible:
            if (
                str(fact.fields.get("trace_id") or "") in trace_ids
                and (fact.evidence_id, fact.locator) not in existing
            ):
                matched.append(fact)

    identity_linked_activities = [
        activity
        for activity in activities
        if _dt(activity.event_time) <= _dt(cutoff)
        and bool(_normalized_scalar_values(activity.details) & identity.lookup_values)
    ]

    # A successful deletion can leave an account readback with no identifier at
    # all.  Correlate only very-near account workflow activity (the workflow
    # report is a claim, not proof) and then use the resource ID solely to locate
    # independent evidence.  The narrow window avoids joining overlapping jobs.
    if not any(fact.resource_id.startswith("account_") for fact in matched):
        reported_at = _dt(request["reported_at"])
        compatible_results = {
            "COMPLETE": {"SUCCESS"},
            "PARTIALLY_COMPLETE": {"SUCCESS", "PARTIAL", "FAILED"},
            "NOT_STARTED": {"FAILED"},
        }.get(request.get("reported_status", ""), set())
        account_candidates = [
            activity
            for activity in activities
            if activity.source_system == "deletion_worker"
            and activity.target_system == "account_service"
            and activity.event_type == "DELETE_RECORD"
            and activity.resource_id.startswith("account_")
            and (not compatible_results or activity.reported_result in compatible_results)
            and _dt(activity.event_time) <= _dt(cutoff)
            and reported_at - timedelta(hours=3)
            <= _dt(activity.event_time)
            <= reported_at + timedelta(minutes=10)
        ]
        if account_candidates:
            expected_operation_time = reported_at - timedelta(minutes=50)
            nearest = min(
                account_candidates,
                key=lambda activity: abs(
                    (_dt(activity.event_time) - expected_operation_time).total_seconds()
                ),
            )
            identity_linked_activities.append(nearest)

    # Expand through concrete resources discovered by identifier matching.
    resource_ids = {
        *[fact.resource_id for fact in matched if fact.resource_id],
        *[activity.resource_id for activity in identity_linked_activities if activity.resource_id],
    }
    matched_keys = {(fact.evidence_id, fact.locator) for fact in matched}
    for fact in eligible:
        if fact.resource_id in resource_ids and (fact.evidence_id, fact.locator) not in matched_keys:
            matched.append(fact)

    # A complete relational snapshot proves absence by omission.  Materialize
    # that negative observation only for a workflow-correlated account ID and
    # only when the snapshot is eligible at the case cutoff.
    account_ids = {resource for resource in resource_ids if resource.startswith("account_")}
    snapshot_facts = [
        fact
        for fact in eligible
        if fact.origin == "customer_account_failover_replica_capture"
        and fact.record_type.startswith("customer_profiles_")
    ]
    if account_ids and snapshot_facts:
        latest_capture = max(fact.captured_at for fact in snapshot_facts)
        latest_snapshot = [fact for fact in snapshot_facts if fact.captured_at == latest_capture]
        present_accounts = {fact.resource_id for fact in latest_snapshot}
        exemplar = latest_snapshot[0]
        already_observed = {fact.resource_id for fact in matched}
        for account_id in sorted(account_ids - present_accounts - already_observed):
            matched.append(
                EvidenceFact(
                    evidence_id=exemplar.evidence_id,
                    file_path=exemplar.file_path,
                    origin=exemplar.origin,
                    captured_at=exemplar.captured_at,
                    source_format=exemplar.source_format,
                    locator=f"complete_snapshot_absence:{account_id}",
                    record_type="USER_PROFILE",
                    system_id="account_service",
                    resource_id=account_id,
                    event_at=exemplar.captured_at,
                    fields={"resource_id": account_id, "state": "ABSENT", "rows": 0},
                )
            )

    related_activities = [
        activity
        for activity in activities
        if activity.resource_id in resource_ids and _dt(activity.event_time) <= _dt(cutoff)
    ]
    related_activity_ids = {activity.activity_id for activity in related_activities}
    related_activities.extend(
        activity
        for activity in identity_linked_activities
        if activity.activity_id not in related_activity_ids
    )
    return {
        "case_id": request["case_id"],
        "audit_at": parse_timestamp(cutoff),
        "user_id": identity.user_id,
        "identifiers": [asdict(item) for item in identity.identifiers],
        "audit_ids": list(identity.audit_ids),
        "resource_ids": sorted(resource_ids),
        "facts": [fact.to_dict() for fact in sorted(matched, key=lambda f: (f.evidence_id, f.locator))],
        "activities": [asdict(item) for item in sorted(related_activities, key=lambda a: (a.event_time, a.activity_id))],
    }


def build_all_contexts(dataset_dir: Path) -> list[dict[str, Any]]:
    resolver = IdentityResolver.from_dataset(dataset_dir)
    documents = ingest_dataset(dataset_dir)
    facts = deduplicate_facts(iter_facts(documents))
    activities = load_activities(dataset_dir)
    with (dataset_dir / "deletion_requests.csv").open(newline="", encoding="utf-8-sig") as handle:
        requests = list(csv.DictReader(handle))
    return [build_case_context(request, resolver, facts, activities) for request in requests]


def write_contexts(contexts: list[dict[str, Any]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for context in sorted(contexts, key=lambda item: item["case_id"]):
            handle.write(json.dumps(context, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(destination)

