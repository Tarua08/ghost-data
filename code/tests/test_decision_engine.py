from __future__ import annotations

import sys
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from decision_engine import (  # noqa: E402
    assess_fact,
    deletion_authorized,
    order_steps,
    validate_predictions,
)


class DecisionEngineTests(unittest.TestCase):
    def test_deletion_and_non_deletion_intent(self) -> None:
        self.assertTrue(deletion_authorized("Please permanently delete my account."))
        self.assertTrue(deletion_authorized("Je demande la suppression définitive du compte."))
        self.assertFalse(deletion_authorized("Please stop the promotional emails."))
        self.assertFalse(deletion_authorized("My surname is misspelled on the account."))

    def test_ordering_and_renumbering(self) -> None:
        steps = [
            {
                "step_no": 9,
                "phase": "VERIFICATION",
                "system_id": "search_service",
                "resource_id": "search_1",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "",
            },
            {
                "step_no": 4,
                "phase": "FINDING",
                "system_id": "search_service",
                "resource_id": "search_1",
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "evidence_id": "evidence_1",
            },
        ]
        ordered = order_steps(steps)
        self.assertEqual(["FINDING", "VERIFICATION"], [item["phase"] for item in ordered])
        self.assertEqual([1, 2], [item["step_no"] for item in ordered])

    def test_rejects_not_applicable_steps(self) -> None:
        with self.assertRaises(ValueError):
            validate_predictions(
                [{"case_id": "case_x", "deletion_status": "NOT_APPLICABLE", "steps": [{}]}]
            )

    def test_anonymized_record_cannot_keep_subject_reference(self) -> None:
        fact = {
            "record_type": "ANALYTICS_PROFILE",
            "resource_id": "analytics_x",
            "system_id": "analytics_platform",
            "evidence_id": "evidence_x",
            "captured_at": "2026-01-01T00:00:00Z",
            "event_at": None,
            "fields": {"customer_reference": "user_1", "email": None},
        }
        assessment = assess_fact(fact, {"ANALYTICS_PROFILE": "ANONYMIZE"})
        self.assertIsNotNone(assessment)
        self.assertFalse(assessment.compliant)


if __name__ == "__main__":
    unittest.main()
