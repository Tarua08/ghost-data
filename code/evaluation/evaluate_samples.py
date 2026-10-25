"""Compare deterministic predictions with the participant-facing sample answers."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from decision_engine import predict_requests  # noqa: E402


def main() -> int:
    dataset = REPO_ROOT / "dataset"
    predictions = {item["case_id"]: item for item in predict_requests(dataset, "sample_deletion_requests.csv")}
    with (dataset / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
        expected = list(csv.DictReader(handle))

    status_correct = 0
    sequence_correct = 0
    expected_steps = predicted_steps = exact_steps = 0
    field_matches = field_total = 0
    fields = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    for row in expected:
        predicted = predictions[row["case_id"]]
        gold_steps = json.loads(row["steps_json"])
        steps = predicted["steps"]
        status_ok = predicted["deletion_status"] == row["deletion_status"]
        sequence_ok = steps == gold_steps
        status_correct += status_ok
        sequence_correct += sequence_ok
        expected_steps += len(gold_steps)
        predicted_steps += len(steps)
        exact_steps += len(
            set(json.dumps(step, sort_keys=True) for step in steps)
            & set(json.dumps(step, sort_keys=True) for step in gold_steps)
        )
        for index, gold_step in enumerate(gold_steps):
            predicted_step = steps[index] if index < len(steps) else {}
            for field in fields:
                field_total += 1
                field_matches += predicted_step.get(field) == gold_step.get(field)
        print(
            f"{row['case_id']}: status={'OK' if status_ok else 'WRONG'} "
            f"steps={len(steps)}/{len(gold_steps)} sequence={'OK' if sequence_ok else 'DIFF'}"
        )
    print(
        json.dumps(
            {
                "status_accuracy": status_correct / len(expected),
                "sequence_accuracy": sequence_correct / len(expected),
                "exact_expected_step_recall": exact_steps / expected_steps,
                "exact_step_precision": exact_steps / predicted_steps if predicted_steps else 0,
                "position_aligned_field_accuracy": field_matches / field_total,
                "expected_steps": expected_steps,
                "predicted_steps": predicted_steps,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
