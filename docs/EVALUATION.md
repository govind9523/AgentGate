# Evaluation

The evaluation suite exercises policy behavior against a versioned JSONL dataset. It records observed outcomes; the dashboard does not pre-populate benchmark scores.

## Run

```sh
python -m evals.run --dataset evals/cases.jsonl --mode both --output evals/reports/latest.json
```

Inspect the generated JSON alongside the exact dataset and source revision used. CI uploads reports as artifacts even when a later check fails. Running a suite locally and passing hosted CI are separate claims.

## Read results

- **Pass/fail:** whether the observed result meets the case expectation.
- **Unauthorized actions:** whether execution crossed the case's defined safety boundary. A blocked response after a write is not the same as preventing the write.
- **Baseline/protected:** equivalent synthetic tasks with the execution boundary disabled or enabled. Baseline is sandbox-only.
- **Precision/recall:** meaningful only when a report defines positive labels and denominators. Missing metrics mean unavailable, not zero.
- **Latency:** measured duration in this environment. It is not a production throughput or tail-latency claim.

Failures should retain the case identifier, expected and observed decisions, relevant findings, and trace or trajectory evidence. Start investigation from the failed case rather than changing an expected result to make the suite pass.

## Coverage and limitations

The project specification's category minima require at least 70 cases. Count the current dataset and inspect category coverage before reporting that requirement as satisfied. Synthetic cases are regression evidence, not representative prevalence data. Pattern detectors can miss paraphrases and unfamiliar formats; shared evaluation and implementation assumptions can conceal bugs.

Do not copy example percentages into a release claim. Publish the report, dataset revision, command, environment, and remaining failures. Performance comparisons should use the same task, seed, tool behavior, and fault profile.
