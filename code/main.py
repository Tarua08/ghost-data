"""Command-line entry point for the deletion-audit agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidence_ingestion import build_summary, ingest_dataset, write_index
from evidence_normalization import build_all_contexts, write_contexts
from decision_engine import predict_requests, validate_predictions, write_predictions
from visual_extraction import extract_all_images


REPO_ROOT = Path(__file__).resolve().parent.parent


def command_ingest(dataset: Path, output: Path) -> int:
    documents = ingest_dataset(dataset)
    write_index(documents, output)
    print(json.dumps(build_summary(documents), indent=2, sort_keys=True))
    print(f"Evidence index: {output}")
    return 0


def command_run(dataset: Path, output: Path, cache_root: Path, requests_file: str) -> int:
    """Execute the complete participant-data pipeline in dependency order."""
    visual_totals = extract_all_images(
        dataset,
        cache_root / "visual",
        REPO_ROOT / ".env",
    )
    documents = ingest_dataset(dataset)
    write_index(documents, cache_root / "evidence_facts.jsonl")
    contexts = build_all_contexts(dataset)
    write_contexts(contexts, cache_root / "case_contexts.jsonl")
    predictions = predict_requests(dataset, requests_file)
    validate_predictions(predictions, expected_rows=len(contexts))
    write_predictions(predictions, output)
    print(
        json.dumps(
            {
                "evidence_documents": len(documents),
                "cases": len(contexts),
                "predictions": len(predictions),
                "visual_calls": visual_totals.calls,
                "visual_cache_hits": visual_totals.cached_files,
                "output": str(output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deletion-audit agent")
    subcommands = parser.add_subparsers(dest="command", required=True)
    ingest = subcommands.add_parser("ingest", help="normalize participant evidence")
    ingest.add_argument("--dataset", type=Path, default=REPO_ROOT / "dataset")
    ingest.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / ".cache" / "evidence_facts.jsonl",
    )
    visual = subcommands.add_parser(
        "extract-images", help="extract structured facts from screenshot evidence"
    )
    visual.add_argument("--dataset", type=Path, default=REPO_ROOT / "dataset")
    visual.add_argument("--cache", type=Path, default=REPO_ROOT / ".cache" / "visual")
    visual.add_argument("--force", action="store_true")
    contexts = subcommands.add_parser(
        "build-contexts", help="resolve identities and build cutoff-safe case contexts"
    )
    contexts.add_argument("--dataset", type=Path, default=REPO_ROOT / "dataset")
    contexts.add_argument(
        "--output", type=Path, default=REPO_ROOT / ".cache" / "case_contexts.jsonl"
    )
    predict = subcommands.add_parser("predict", help="generate final deletion-audit predictions")
    predict.add_argument("--dataset", type=Path, default=REPO_ROOT / "dataset")
    predict.add_argument("--requests", default="deletion_requests.csv")
    predict.add_argument("--output", type=Path, default=REPO_ROOT / "output.csv")
    run = subcommands.add_parser("run", help="run extraction, normalization, reasoning, and export")
    run.add_argument("--dataset", type=Path, default=REPO_ROOT / "dataset")
    run.add_argument("--requests", default="deletion_requests.csv")
    run.add_argument("--output", type=Path, default=REPO_ROOT / "output.csv")
    run.add_argument("--cache", type=Path, default=REPO_ROOT / ".cache")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "ingest":
        return command_ingest(args.dataset.resolve(), args.output.resolve())
    if args.command == "extract-images":
        totals = extract_all_images(
            args.dataset.resolve(),
            args.cache.resolve(),
            REPO_ROOT / ".env",
            force=args.force,
        )
        print(json.dumps(totals.__dict__, indent=2, sort_keys=True))
        return 0
    if args.command == "build-contexts":
        contexts = build_all_contexts(args.dataset.resolve())
        write_contexts(contexts, args.output.resolve())
        summary = {
            "cases": len(contexts),
            "facts": sum(len(item["facts"]) for item in contexts),
            "activities": sum(len(item["activities"]) for item in contexts),
            "cases_with_facts": sum(bool(item["facts"]) for item in contexts),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        print(f"Case contexts: {args.output.resolve()}")
        return 0
    if args.command == "predict":
        predictions = predict_requests(args.dataset.resolve(), args.requests)
        write_predictions(predictions, args.output.resolve())
        print(
            json.dumps(
                {
                    "rows": len(predictions),
                    "statuses": {
                        status: sum(item["deletion_status"] == status for item in predictions)
                        for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        print(f"Predictions: {args.output.resolve()}")
        return 0
    if args.command == "run":
        return command_run(
            args.dataset.resolve(),
            args.output.resolve(),
            args.cache.resolve(),
            args.requests,
        )
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
