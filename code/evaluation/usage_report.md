# Model usage report

## Final output-producing pipeline

Only screenshot extraction used a model. CSV, JSON, SQL, logs, text, native PDF
text, identity resolution, cutoff filtering, policy evaluation, ordering, and CSV
generation were deterministic Python operations.

| Provider | Model | Calls | Input tokens | Candidate tokens | Other output/thinking tokens | Total tokens |
|---|---|---:|---:|---:|---:|---:|
| Google | `gemini-3.8-flash` | 11 | 14,282 | 13,861 | 29,771 | 57,914 |
| **Overall** | | **11** | **14,282** | **13,861** | **29,771** | **57,914** |

- Average total tokens per model call: 5,265
- Average total model tokens per deletion request: 111.8
- The 11 image results are cached by evidence hash, model, and prompt version.
  Rebuilding all 518 predictions makes zero additional model calls while the
  inputs and configuration are unchanged.

Using the public introductory list prices applicable during the run
($0.75/million input tokens and $3.75/million output tokens, including thinking),
the estimated list-price cost is approximately **$0.1743 total**, or **$0.00034
per deletion request**. Actual billed cost may be zero or differ based on the
account's tier and credits.

The earlier connectivity smoke test is excluded because it did not contribute to
`output.csv`. Credentials are loaded only from the ignored local `.env` file and
are not included in this report, source tree, logs, or submission artifacts.
