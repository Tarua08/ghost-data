from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from evidence_ingestion import ingest_dataset, iter_facts  # noqa: E402
from evidence_normalization import (  # noqa: E402
    build_case_context,
    deduplicate_facts,
    fact_is_eligible,
    load_activities,
)
from identity_resolution import IdentityResolver  # noqa: E402


class IdentityAndContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = REPO_ROOT / "dataset"
        cls.resolver = IdentityResolver.from_dataset(cls.dataset)
        cls.facts = deduplicate_facts(iter_facts(ingest_dataset(cls.dataset)))
        cls.activities = load_activities(cls.dataset)
        with (cls.dataset / "sample_deletion_requests.csv").open(
            newline="", encoding="utf-8-sig"
        ) as handle:
            cls.sample_requests = {row["case_id"]: row for row in csv.DictReader(handle)}

    def test_historical_email_resolves_to_current_subject(self) -> None:
        resolved = self.resolver.resolve(
            "camille.bernard86@outlook.com", "2026-09-15T12:00:00Z"
        )
        self.assertEqual("user_30", resolved.user_id)
        values = {item.normalized for item in resolved.identifiers}
        self.assertIn("camille.bernard86@outlook.com", values)
        self.assertIn("camille.bernard@outlook.com", values)

    def test_future_capture_is_not_eligible(self) -> None:
        future = next(fact for fact in self.facts if fact.evidence_id == "evidence_02")
        self.assertFalse(fact_is_eligible(future, "2026-09-15T12:00:00Z"))

    def test_case_30_context_uses_eligible_evidence(self) -> None:
        context = build_case_context(
            self.sample_requests["case_30"], self.resolver, self.facts, self.activities
        )
        evidence_ids = {fact["evidence_id"] for fact in context["facts"]}
        self.assertIn("evidence_92", evidence_ids)
        self.assertNotIn("evidence_02", evidence_ids)
        self.assertIn("analytics_3697", context["resource_ids"])
        self.assertIn("data_flow_8524", context["resource_ids"])

    def test_complete_snapshot_materializes_correlated_absence(self) -> None:
        context = build_case_context(
            self.sample_requests["case_01"], self.resolver, self.facts, self.activities
        )
        account = next(fact for fact in context["facts"] if fact["resource_id"] == "account_001")
        self.assertEqual("evidence_54", account["evidence_id"])
        self.assertEqual("ABSENT", account["fields"]["state"])

    def test_visual_duplicate_is_collapsed(self) -> None:
        matches = [
            fact
            for fact in self.facts
            if fact.evidence_id == "evidence_37" and fact.resource_id == "audit_record_003"
        ]
        self.assertEqual(1, len(matches))

    def test_manifest_origin_canonicalizes_visual_system(self) -> None:
        marketing = [
            fact
            for fact in self.facts
            if fact.evidence_id == "evidence_60" and fact.resource_id == "marketing_001"
        ]
        self.assertEqual(1, len(marketing))
        self.assertEqual("marketing_platform", marketing[0].system_id)

    def test_json_schema_variants_preserve_system_and_event_time(self) -> None:
        fact = next(
            fact
            for fact in self.facts
            if fact.evidence_id == "evidence_13" and fact.resource_id == "data_flow_4227"
        )
        self.assertEqual("integration_service", fact.system_id)
        self.assertEqual("DATA_FLOW", fact.record_type)
        self.assertEqual("2026-08-12T09:00:00Z", fact.event_at)

    def test_all_requests_resolve_to_one_identity(self) -> None:
        for filename in ("sample_deletion_requests.csv", "deletion_requests.csv"):
            with (self.dataset / filename).open(newline="", encoding="utf-8-sig") as handle:
                for request in csv.DictReader(handle):
                    with self.subTest(filename=filename, case_id=request["case_id"]):
                        resolved = self.resolver.resolve(request["email"], request["audit_at"])
                        self.assertTrue(resolved.user_id.startswith("user_"))


if __name__ == "__main__":
    unittest.main()
