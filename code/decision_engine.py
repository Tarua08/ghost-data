"""Deterministic deletion intent, policy assessment, and step generation."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from evidence_ingestion import EvidenceFact, ingest_dataset, iter_facts
from evidence_normalization import (
    build_case_context,
    deduplicate_facts,
    load_activities,
)
from identity_resolution import IdentityResolver


PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
NON_DELETION_MARKERS = (
    "mobile number on my profile is out of date",
    "stop the promotional emails",
    "download my account information in a portable format",
    "help resetting the login",
    "surname is misspelled",
    "marketing lists only",
    "information request, not a request to erase",
    "copy of last year's invoices",
    "change the email address used for this account",
    "still use it, so please don't delete",
)
DELETION_MARKERS = (
    "delete",
    "deletion",
    "erase",
    "erased",
    "remove my account",
    "close my account",
    "account deletion",
    "suppression",
    "eliminación",
    "eliminar",
    "exclusão",
    "削除",
    "영구 삭제",
)
CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE",
    "DATA_FLOW",
}


def deletion_authorized(text: str) -> bool:
    lowered = text.casefold()
    if any(marker in lowered for marker in NON_DELETION_MARKERS):
        return False
    # Challenge requests are deletion audits unless they explicitly authorize a
    # different privacy action. This also covers natural phrases such as
    # "closed", "disconnected", and "no longer need this account".
    return True


def load_policy(dataset_dir: Path) -> dict[str, str]:
    policy: dict[str, str] = {}
    with (dataset_dir / "deletion_rules.csv").open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            policy[row["data_category"].strip()] = row["required_action"].strip()
    return policy


def _upper(value: Any) -> str:
    return str(value or "").strip().upper().replace(" ", "_")


def infer_category(fact: dict[str, Any]) -> str | None:
    fields = fact["fields"]
    for key in ("data_category", "category", "record_type"):
        candidate = _upper(fields.get(key))
        if candidate in CATEGORIES:
            return candidate
    record_type = _upper(fact.get("record_type"))
    aliases = {
        "CUSTOMER_PROFILES": "USER_PROFILE",
        "CUSTOMER_PROFILES_FAILOVER_REPLICA": "USER_PROFILE",
        "PROFILE_LOOKUPS": "USER_PROFILE",
        "PROFILE_LOOKUP_COMPLETED": "USER_PROFILE",
        "CUSTOMER_SEARCH_DOCUMENTS": "SEARCH_INDEX_ENTRY",
        "SEARCH_DOCUMENTS_PRIMARY": "SEARCH_INDEX_ENTRY",
        "INDEX_QUERIES": "SEARCH_INDEX_ENTRY",
        "INDEX_QUERY_COMPLETED": "SEARCH_INDEX_ENTRY",
        "CUSTOMER_ANALYTICS_PROFILES": "ANALYTICS_PROFILE",
        "PROFILES": "ANALYTICS_PROFILE",
        "ANALYTICS_PROFILE_READ_COMPLETED": "ANALYTICS_PROFILE",
        "ANALYTICS_IDENTITY_SCAN": "ANALYTICS_PROFILE",
        "SUPPORT_RECORDS": "SUPPORT_MESSAGE",
        "TICKET": "SUPPORT_MESSAGE",
        "TICKETS": "SUPPORT_MESSAGE",
        "SUPPORT_TICKET_READ_COMPLETED": "SUPPORT_MESSAGE",
        "MESSAGE_PII_SCAN": "SUPPORT_MESSAGE",
        "MESSAGE_READ": "SUPPORT_MESSAGE",
        "ATTACHMENT_PII_SCAN": "SUPPORT_ATTACHMENT",
        "CONTACT_QUERY_COMPLETED": "SECONDARY_IDENTIFIER",
        "CONTACT_LOOKUP_COMPLETED": "SECONDARY_IDENTIFIER",
        "CUSTOMER_EXPORTS": "USER_EXPORT",
        "EXPORTS": "USER_EXPORT",
        "CONNECTOR_SUBSCRIPTIONS": "DATA_FLOW",
        "CONNECTORS": "DATA_FLOW",
        "CONNECTOR_HEARTBEAT": "DATA_FLOW",
        "CONNECTOR_CONFIG_READ_COMPLETED": "DATA_FLOW",
        "BACKUP_RESTORE_ENTRIES": "BACKUP_ARCHIVE",
        "RESTORE_ENTRIES": "BACKUP_ARCHIVE",
        "SECURITY_AUDIT_RECORDS": "SECURITY_AUDIT_LOG",
        "AUDIT_RECORDS": "SECURITY_AUDIT_LOG",
        "AUDIT_RECORD_READ_COMPLETED": "SECURITY_AUDIT_LOG",
    }
    if record_type in CATEGORIES:
        return record_type
    if record_type in aliases:
        return aliases[record_type]
    resource = fact.get("resource_id", "")
    prefix_categories = (
        ("account_", "USER_PROFILE"),
        ("search_", "SEARCH_INDEX_ENTRY"),
        ("analytics_", "ANALYTICS_PROFILE"),
        ("support_", "SUPPORT_MESSAGE"),
        ("export_", "USER_EXPORT"),
        ("data_flow_", "DATA_FLOW"),
        ("backup_", "BACKUP_ARCHIVE"),
        ("audit_record_", "SECURITY_AUDIT_LOG"),
        ("tombstone_", "ACCOUNT_TOMBSTONE"),
        ("marketing_", "MARKETING_PROFILE"),
        ("legal_hold_", "LEGAL_HOLD_RECORD"),
        ("cache_", "CACHE_ENTRY"),
        ("email_delivery_", "EMAIL_DELIVERY_LOG"),
    )
    return next((category for prefix, category in prefix_categories if resource.startswith(prefix)), None)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().casefold()
    if lowered in {"1", "true", "yes", "enabled", "active", "allowed"}:
        return True
    if lowered in {"0", "false", "no", "disabled", "stopped", "blocked"}:
        return False
    return None


def _state_tokens(fields: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("state", "result", "status", "account_status", "last_delivery_status"):
        value = fields.get(key)
        if value not in (None, ""):
            tokens.add(_upper(value))
    for key in ("status_code", "http_status"):
        if fields.get(key) not in (None, ""):
            tokens.add(str(fields[key]))
    if str(fields.get("rows", "")).strip() == "0":
        tokens.add("ABSENT")
    return tokens


def _direct_pii_present(fields: dict[str, Any]) -> bool:
    pii_keys = (
        "email",
        "requester_email",
        "owner_email",
        "customer_email",
        "phone",
        "requester_phone",
        "owner_phone",
        "full_name",
        "name",
        "display_name",
        "email_hash",
    )
    if any(fields.get(key) not in (None, "", "[REDACTED]") for key in pii_keys):
        return True
    text = json.dumps(fields, ensure_ascii=False)
    return bool(re.search(r"(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", text))


def _still_attributable(fields: dict[str, Any]) -> bool:
    if _direct_pii_present(fields):
        return True
    return any(
        fields.get(key) not in (None, "", "[REDACTED]")
        for key in ("user_id", "customer_reference", "subject_reference")
    )


@dataclass(frozen=True)
class Assessment:
    fact: dict[str, Any]
    category: str
    required_action: str
    compliant: bool
    final_operation: str
    final_state: str


def assess_fact(fact: dict[str, Any], policy: dict[str, str]) -> Assessment | None:
    if fact["record_type"] == "image_artifact" or not fact.get("resource_id"):
        return None
    category = infer_category(fact)
    if category is None:
        return None
    fields = fact["fields"]
    tokens = _state_tokens(fields)

    if category == "DATA_FLOW":
        enabled = _bool(fields.get("enabled"))
        compliant = enabled is False or bool(tokens & {"DISABLED", "STOPPED", "INACTIVE"})
        return Assessment(fact, category, "DISABLE", compliant, "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
    if category == "BACKUP_ARCHIVE":
        allowed = _bool(fields.get("restore_allowed"))
        compliant = allowed is False or bool(tokens & {"BLOCKED", "RESTORE_BLOCKED"})
        return Assessment(fact, category, "BLOCK", compliant, "VERIFY_RESTORE_BLOCKED", "BLOCKED")

    action = policy.get(category)
    if action is None:
        return None
    if category == "SECURITY_AUDIT_LOG" and fields.get("retention_until"):
        retention = str(fields["retention_until"])
        observed = fact.get("event_at") or fact.get("captured_at") or ""
        if observed and retention < observed:
            return None
    if category == "LEGAL_HOLD_RECORD":
        active = _bool(fields.get("active"))
        hold_state = _upper(fields.get("status"))
        if active is False or hold_state in {"RELEASED", "EXPIRED", "INACTIVE"}:
            return None
    absent = bool(tokens & {"NOT_FOUND", "ABSENT", "MISS", "404"}) or fields.get("profile", "sentinel") is None
    if action == "DELETE":
        compliant = absent
        final_operation, final_state = "VERIFY_RECORD_ABSENT", "ABSENT"
    elif action == "REDACT":
        compliant = not _direct_pii_present(fields) or bool(tokens & {"REDACTED"})
        final_operation, final_state = "VERIFY_RECORD_REDACTED", "REDACTED"
    elif action == "ANONYMIZE":
        compliant = not _still_attributable(fields) or bool(tokens & {"ANONYMIZED"})
        final_operation, final_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    elif action == "RETAIN":
        compliant = not absent
        final_operation, final_state = "VERIFY_RECORD_PRESENT", "PRESENT"
    else:
        return None
    return Assessment(fact, category, action, compliant, final_operation, final_state)


def _step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def finding_for(assessment: Assessment) -> dict[str, Any]:
    operation = {
        "DELETE": "REPORT_REMAINING_RECORD",
        "REDACT": "REPORT_EXPOSED_PII",
        "ANONYMIZE": "REPORT_EXPOSED_PII",
        "DISABLE": "REPORT_ACTIVE_DATA_FLOW",
        "BLOCK": "REPORT_RESTORE_RISK",
    }[assessment.required_action]
    state = "ACTIVE" if operation in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT"
    fact = assessment.fact
    return _step("FINDING", fact["system_id"], fact["resource_id"], operation, state, fact["evidence_id"])


def remediation_for(assessment: Assessment) -> dict[str, Any]:
    operation, state = {
        "DELETE": ("DELETE_RECORD", "ABSENT"),
        "REDACT": ("REDACT_RECORD", "REDACTED"),
        "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
        "DISABLE": ("DISABLE_DATA_FLOW", "DISABLED"),
        "BLOCK": ("BLOCK_RESTORE", "BLOCKED"),
    }[assessment.required_action]
    fact = assessment.fact
    return _step("REMEDIATION", fact["system_id"], fact["resource_id"], operation, state, "")


def verification_for(assessment: Assessment, evidence_id: str) -> dict[str, Any]:
    fact = assessment.fact
    return _step(
        "VERIFICATION",
        fact["system_id"],
        fact["resource_id"],
        assessment.final_operation,
        assessment.final_state,
        evidence_id,
    )


def order_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for step in steps:
        key = (step["phase"], step["operation"], step["system_id"], step["resource_id"])
        unique.setdefault(key, step)
    ordered = sorted(
        unique.values(),
        key=lambda step: (
            PHASE_ORDER[step["phase"]],
            OPERATION_ORDER[step["operation"]],
            step["system_id"],
            step["resource_id"],
        ),
    )
    for number, step in enumerate(ordered, start=1):
        step["step_no"] = number
    return ordered


def decide_case(request: dict[str, str], context: dict[str, Any], policy: dict[str, str]) -> dict[str, Any]:
    if not deletion_authorized(request["request_text"]):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps": []}

    assessments = [item for fact in context["facts"] if (item := assess_fact(fact, policy))]
    # One evidence snapshot may show the same resource more than once; retain the
    # richest/latest normalized observation selected upstream.
    by_resource: dict[tuple[str, str], Assessment] = {}
    for assessment in assessments:
        key = (assessment.fact["system_id"], assessment.fact["resource_id"])
        previous = by_resource.get(key)
        if previous is None or (
            assessment.fact.get("captured_at", ""),
            assessment.fact.get("event_at") or "",
        ) > (
            previous.fact.get("captured_at", ""),
            previous.fact.get("event_at") or "",
        ):
            by_resource[key] = assessment
    assessments = list(by_resource.values())
    violations = [item for item in assessments if not item.compliant]

    if violations:
        steps = [finding_for(item) for item in violations]
        steps.extend(remediation_for(item) for item in violations)
        steps.extend(verification_for(item, "") for item in assessments)
        status = "INCOMPLETE"
    else:
        steps = [verification_for(item, item.fact["evidence_id"]) for item in assessments]
        status = "COMPLETE"
    return {"case_id": request["case_id"], "deletion_status": status, "steps": order_steps(steps)}


def predict_requests(dataset_dir: Path, requests_file: str) -> list[dict[str, Any]]:
    resolver = IdentityResolver.from_dataset(dataset_dir)
    facts = deduplicate_facts(iter_facts(ingest_dataset(dataset_dir)))
    activities = load_activities(dataset_dir)
    policy = load_policy(dataset_dir)
    with (dataset_dir / requests_file).open(newline="", encoding="utf-8-sig") as handle:
        requests = list(csv.DictReader(handle))
    predictions = []
    for request in requests:
        context = build_case_context(request, resolver, facts, activities)
        predictions.append(decide_case(request, context, policy))
    return predictions


def write_predictions(predictions: list[dict[str, Any]], destination: Path) -> None:
    validate_predictions(predictions)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for prediction in sorted(predictions, key=lambda item: item["case_id"]):
            writer.writerow(
                {
                    "case_id": prediction["case_id"],
                    "deletion_status": prediction["deletion_status"],
                    "steps_json": json.dumps(prediction["steps"], ensure_ascii=False, separators=(",", ":")),
                }
            )
    temporary.replace(destination)


def validate_predictions(predictions: list[dict[str, Any]], expected_rows: int | None = None) -> None:
    if expected_rows is not None and len(predictions) != expected_rows:
        raise ValueError(f"Expected {expected_rows} predictions; found {len(predictions)}")
    case_ids = [item["case_id"] for item in predictions]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Duplicate case_id in predictions")
    valid_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    required_keys = {
        "step_no",
        "phase",
        "system_id",
        "resource_id",
        "operation",
        "state",
        "evidence_id",
    }
    for prediction in predictions:
        if prediction["deletion_status"] not in valid_statuses:
            raise ValueError(f"Invalid status for {prediction['case_id']}")
        steps = prediction["steps"]
        if prediction["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE case has steps: {prediction['case_id']}")
        if [step["step_no"] for step in steps] != list(range(1, len(steps) + 1)):
            raise ValueError(f"Nonconsecutive step numbers: {prediction['case_id']}")
        if steps != order_steps([dict(step) for step in steps]):
            raise ValueError(f"Incorrect step ordering: {prediction['case_id']}")
        for step in steps:
            if set(step) != required_keys:
                raise ValueError(f"Invalid step fields: {prediction['case_id']}")
            if step["phase"] in {"REMEDIATION", "VERIFICATION"} and prediction["deletion_status"] == "INCOMPLETE":
                if step["evidence_id"]:
                    raise ValueError(f"Future step cites evidence: {prediction['case_id']}")

