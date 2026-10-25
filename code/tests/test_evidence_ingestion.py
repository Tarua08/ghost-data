from __future__ import annotations

import sys
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from evidence_ingestion import ingest_dataset, load_manifest  # noqa: E402


class EvidenceIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = REPO_ROOT / "dataset"
        cls.documents = ingest_dataset(cls.dataset)

    def test_every_manifest_entry_is_ingested_once(self) -> None:
        manifest = load_manifest(self.dataset)
        self.assertEqual(94, len(manifest))
        self.assertEqual(len(manifest), len(self.documents))
        self.assertEqual(
            {entry.evidence_id for entry in manifest},
            {document.entry.evidence_id for document in self.documents},
        )

    def test_every_document_has_content_and_hash(self) -> None:
        for document in self.documents:
            with self.subTest(evidence_id=document.entry.evidence_id):
                self.assertGreater(document.byte_size, 0)
                self.assertEqual(64, len(document.sha256))
                self.assertGreater(len(document.facts), 0)

    def test_provenance_and_time_are_preserved(self) -> None:
        for document in self.documents:
            for fact in document.facts:
                with self.subTest(evidence_id=fact.evidence_id, locator=fact.locator):
                    self.assertEqual(document.entry.evidence_id, fact.evidence_id)
                    self.assertEqual(document.entry.captured_at, fact.captured_at)
                    self.assertTrue(fact.locator)
                    self.assertTrue(fact.record_type)

    def test_all_expected_formats_are_covered(self) -> None:
        formats = {fact.source_format for doc in self.documents for fact in doc.facts}
        self.assertEqual({"image", "json", "log", "pdf", "sql", "text"}, formats)

    def test_wrapped_log_formats_preserve_resource_and_trace(self) -> None:
        facts = [fact for document in self.documents for fact in document.facts]
        nested = next(
            fact
            for fact in facts
            if fact.evidence_id == "evidence_25" and fact.resource_id == "support_2498"
        )
        self.assertEqual("message_pii_scan", nested.record_type)
        self.assertEqual("support_platform", nested.system_id)
        self.assertEqual("tr-0305307", nested.fields["trace_id"])
        syslog = next(
            fact
            for fact in facts
            if fact.evidence_id == "evidence_39" and fact.record_type == "profile_lookup_started"
        )
        self.assertEqual("account_service", syslog.system_id)
        self.assertTrue(syslog.fields["trace_id"].startswith("tr-"))


if __name__ == "__main__":
    unittest.main()
