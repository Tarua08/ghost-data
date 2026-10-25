from __future__ import annotations

import sys
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from visual_extraction import _validate_result  # noqa: E402


class VisualExtractionValidationTests(unittest.TestCase):
    def test_valid_payload(self) -> None:
        payload = {
            "document_text": "Account record",
            "records": [
                {
                    "system_id": "account_service",
                    "resource_id": "account_1",
                    "record_type": "USER_PROFILE",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "state": "FOUND",
                    "identifiers": [{"type": "email", "value": "person@example.com"}],
                    "attributes": [],
                    "visible_text": "account_1 FOUND",
                    "region": "row 1",
                }
            ],
        }
        self.assertEqual(payload, _validate_result(payload))

    def test_rejects_extra_fields(self) -> None:
        with self.assertRaises(ValueError):
            _validate_result(
                {
                    "document_text": "x",
                    "records": [{"unexpected": "invented"}],
                }
            )


if __name__ == "__main__":
    unittest.main()
