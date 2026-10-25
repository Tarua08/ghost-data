# Ghost Data Deletion Audit Agent

This submission reconstructs each person's current and historical identity, finds matching evidence as it existed at the request's audit cutoff, applies `deletion_rules.csv`, detects recreation paths, and emits the exact required `output.csv` schema.

## Approach

The pipeline is deliberately hybrid:

1. Deterministic parsers normalize JSON, SQLite-flavoured SQL dumps, logs, text, and PDFs into provenance-preserving facts.
2. Gemini is used only as a bounded visual extractor for screenshots. It returns schema-constrained visible facts; it never decides deletion status.
3. An identity graph joins current and historical user IDs, email addresses, normalized phones, hashes, and explicit aliases.
4. Cutoff-safe matching excludes evidence captured or created after `audit_at` and follows trace/catalogue links where the dataset explicitly supports them.
5. A deterministic policy engine applies the supplied deletion rules and produces ordered `DISCOVERY`, `REMEDIATION`, and `VERIFICATION` steps.
6. A strict validator checks status values, row uniqueness, step fields, numbering, ordering, and evidence provenance before CSV export.

This split keeps policy decisions reproducible while still reading image-only evidence.

## Setup

Python 3.11 is recommended. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r code/requirements.txt
cp code/.env.example .env
```

Put the Gemini API key in the local `.env`. The file is ignored by Git and must not be included in the submission. The supplied `dataset/` directory must remain beside `code/`.

## Run

Generate the final predictions with one command:

```bash
python3 code/main.py run
```

This writes `output.csv` at the repository root and intermediate, content-addressed artifacts under `.cache/`. A fresh run calls Gemini once for each screenshot. Later runs reuse validated cached extraction results and do not require a key when every screenshot is cached.

Individual stages are also available:

```bash
python3 code/main.py extract-images
python3 code/main.py ingest
python3 code/main.py build-contexts
python3 code/main.py predict
```

## Evaluation

Run unit tests and the organizer-provided labeled-sample evaluation:

```bash
python3 -m unittest discover -s code/tests -v
python3 code/evaluation/main.py
```

The evaluator generates predictions without reading expected labels, then compares them with `sample_output.csv`. Hidden/evaluation labels are never used by the prediction pipeline.

## Security and operational controls

- Manifest paths are confined to `dataset/`; duplicate evidence IDs and missing files fail closed.
- SQLite dumps are opened in memory with an authorizer and instruction limit.
- Model output is schema validated, cached by image hash/model/prompt version, and treated as extracted evidence rather than policy truth.
- Every output fact retains its evidence ID and locator; future remediation never claims an evidence citation.
- API keys, datasets, virtual environments, caches, and generated outputs are excluded from `code.zip`.
