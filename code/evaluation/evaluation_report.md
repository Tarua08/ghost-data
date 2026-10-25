# Evaluation report

## Published sample evaluation

The deterministic pipeline was evaluated against all 32 rows in
`dataset/sample_deletion_requests.csv` and `dataset/sample_output.csv`.

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | 100.00% (32/32) |
| Exact sequence accuracy | 50.00% (16/32) |
| Exact expected-step recall | 80.83% (156/193) |
| Exact step precision | 87.64% (156/178) |
| Position-aligned field accuracy | 86.68% |

Run the evaluation with:

```bash
python3 code/evaluation/main.py
```

The evaluator reports every case, predicted and expected step counts, exact
sequence equality, exact step precision/recall, and field accuracy. It uses only
the organizer-provided public sample output for scoring and never reads it during
prediction generation.

## Additional participant-created checks

1. **Non-deletion intent:** a marketing-only opt-out produces
   `NOT_APPLICABLE` with an empty step list.
2. **Historical identifier:** Camille's former email resolves to the current
   stable `user_30`, and both eligible email forms and their hashes are searched.
3. **Temporal isolation:** `evidence_02`, captured after case 30's `audit_at`, is
   excluded even though it contains useful later observations.
4. **Duplicate visual presentation:** a security row repeated in a screenshot's
   details panel is collapsed to one resource observation.
5. **Future-step citations:** incomplete-case remediation and verification steps
   are rejected if they contain an evidence citation.

These checks are automated under `code/tests/` and run with:

```bash
python3 -m unittest discover -s code/tests -v
```

## Failures found and improvements made

- The first intent classifier required narrow deletion keywords and reached only
  62.5% status accuracy. Explicitly recognizing the supplied non-deletion intents
  while allowing natural deletion wording raised status accuracy to 100%.
- Log identifiers and resource IDs often appear on separate lines. Joining only
  records with an exact shared `trace_id` recovered the missing resources without
  fuzzy inference.
- JSON exports use multiple schema variants (`system`/`system_id` and
  `recorded_at`/`observed_at`). Supporting both restored canonical systems and
  internal event-time enforcement.
- Gemini sometimes extracted a table row and its detail panel twice. Records are
  now deduplicated by evidence ID, canonical system, and resource ID.
- Native PDF page text did not initially create resource facts. Resource IDs are
  now extracted from the complete document while retaining page provenance.
- Identifier-free deletion readbacks initially disappeared from the case graph.
  A tightly bounded workflow-resource join now connects them to complete
  snapshots, where absence is represented explicitly rather than inferred from
  a successful operation claim.
- Overlapping deletion jobs initially made nearest-event matching unreliable.
  Correlation now constrains account operations by workflow outcome and the
  observed reporting cadence, while independent evidence still determines the
  resource state.
- Multiple observations of one resource initially depended on lexical evidence
  ordering. The policy engine now chooses the latest eligible observation.
- An analytics record that retained an internal subject reference was initially
  treated as anonymous. Attribution checks now include stable subject and
  customer references while still permitting them in policy-compliant account
  tombstones.
- Three structured-log dialects hid fields inside cloud-runtime messages,
  syslog headers, and pipe-delimited envelopes. Dedicated parsers now preserve
  their service, event, trace, resource, and nested key/value fields so exact
  trace joins work across all supplied log exports.

## Remaining limitation

Several expected sample verification steps cite resources that do not occur in
the participant evidence file named by those steps. The system does not invent
those resource IDs. This preserves evidence integrity but lowers exact step and
sequence scores while leaving status accuracy intact. The next improvement would
be an organizer-provided scoped resource map or explicit workflow correlation ID;
time proximity alone is unsafe because unrelated deletion workflows overlap.
