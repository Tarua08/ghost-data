"""Deterministic current and historical identity resolution."""

from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from evidence_ingestion import parse_timestamp


IDENTITY_FIELDS = ("name", "email", "phone", "email_hash")


def _dt(value: str) -> datetime:
    canonical = parse_timestamp(value)
    if canonical is None:
        raise ValueError(f"Invalid timestamp: {value}")
    return datetime.fromisoformat(canonical.replace("Z", "+00:00"))


def normalize_identifier(kind: str, value: str) -> str:
    value = str(value or "").strip()
    if kind == "email":
        return value.casefold()
    if kind == "email_hash":
        return value.casefold()
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return f"+{digits}" if digits else ""
    if kind in {"user_id", "subject_reference", "customer_reference"}:
        return value.casefold()
    return value.casefold()


def email_hash(email: str) -> str:
    return hashlib.sha256(normalize_identifier("email", email).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditChange:
    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class Identifier:
    kind: str
    value: str
    normalized: str
    source: str


@dataclass(frozen=True)
class ResolvedIdentity:
    user_id: str
    identifiers: tuple[Identifier, ...]
    audit_ids: tuple[str, ...]

    @property
    def lookup_values(self) -> set[str]:
        return {item.normalized for item in self.identifiers if item.normalized}


class IdentityResolver:
    def __init__(self, identities: dict[str, dict[str, str]], changes: list[AuditChange]):
        self.identities = identities
        self.changes = sorted(changes, key=lambda item: (_dt(item.event_time), item.audit_id))
        self.changes_by_user: dict[str, list[AuditChange]] = {}
        for change in self.changes:
            self.changes_by_user.setdefault(change.user_id, []).append(change)
        self.email_to_users: dict[str, set[str]] = {}
        for user_id, row in identities.items():
            self._index_email(user_id, row.get("email", ""))
        for change in changes:
            if change.field_name == "email":
                self._index_email(change.user_id, change.old_value)
                self._index_email(change.user_id, change.new_value)

    @classmethod
    def from_dataset(cls, dataset_dir: Path) -> "IdentityResolver":
        identities: dict[str, dict[str, str]] = {}
        with (dataset_dir / "user_identities.csv").open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                user_id = row["user_id"].strip()
                if user_id in identities:
                    raise ValueError(f"Duplicate user identity: {user_id}")
                identities[user_id] = {key: str(value or "").strip() for key, value in row.items()}
        changes: list[AuditChange] = []
        with (dataset_dir / "user_audit_log.csv").open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                changes.append(
                    AuditChange(
                        audit_id=row["audit_id"].strip(),
                        user_id=row["user_id"].strip(),
                        event_time=parse_timestamp(row["event_time"]) or "",
                        field_name=row["field_name"].strip(),
                        old_value=row["old_value"].strip(),
                        new_value=row["new_value"].strip(),
                    )
                )
        return cls(identities, changes)

    def _index_email(self, user_id: str, value: str) -> None:
        normalized = normalize_identifier("email", value)
        if normalized:
            self.email_to_users.setdefault(normalized, set()).add(user_id)

    def subject_for_email(self, request_email: str) -> str:
        matches = self.email_to_users.get(normalize_identifier("email", request_email), set())
        if len(matches) != 1:
            raise ValueError(
                f"Expected one identity for {request_email!r}; found {sorted(matches)}"
            )
        return next(iter(matches))

    def resolve(self, request_email: str, cutoff: str) -> ResolvedIdentity:
        user_id = self.subject_for_email(request_email)
        cutoff_dt = _dt(cutoff)
        current = dict(self.identities[user_id])
        user_changes = self.changes_by_user.get(user_id, [])

        # Rewind the current snapshot through changes that occurred after cutoff.
        for change in reversed(user_changes):
            if _dt(change.event_time) > cutoff_dt and change.field_name in IDENTITY_FIELDS:
                current[change.field_name] = change.old_value

        identifiers: dict[tuple[str, str], Identifier] = {}

        def add(kind: str, value: str, source: str) -> None:
            normalized = normalize_identifier(kind, value)
            if normalized:
                identifiers.setdefault(
                    (kind, normalized),
                    Identifier(kind=kind, value=value, normalized=normalized, source=source),
                )

        add("user_id", user_id, "stable_identity")
        for field in IDENTITY_FIELDS:
            add(field, current.get(field, ""), "state_at_cutoff")

        eligible_audits: list[str] = []
        for change in user_changes:
            if _dt(change.event_time) <= cutoff_dt:
                eligible_audits.append(change.audit_id)
                if change.field_name in IDENTITY_FIELDS:
                    add(change.field_name, change.old_value, change.audit_id)
                    add(change.field_name, change.new_value, change.audit_id)

        # Hash every eligible email because older systems may store only its digest.
        emails = [item.value for item in identifiers.values() if item.kind == "email"]
        for value in emails:
            add("email_hash", email_hash(value), "derived_from_email")

        return ResolvedIdentity(
            user_id=user_id,
            identifiers=tuple(sorted(identifiers.values(), key=lambda item: (item.kind, item.normalized))),
            audit_ids=tuple(eligible_audits),
        )

