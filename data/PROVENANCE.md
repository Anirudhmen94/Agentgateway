# Eval label provenance

Eval lives in `data/`. Every gold label is **human-authored**. No row is labeled by grok-4.6, by the local fallback, or by an automated scorer.

| File | Rows | Who wrote labels | What the bytes are |
| --- | ---: | --- | --- |
| `eval_set.jsonl` | 200 | Human, in `scripts/generate_eval_set.py` | Synthetic agents and synthetic tool calls. |
| `eval_adversarial.jsonl` | 21 | Human, in `scripts/generate_adversarial_eval.py` | Synthetic paraphrases, pagination/bulk walks, and approve-without-ACK cases aimed at keyword misses. |

Adversarial rows also carry `label_provenance: human` and `data_provenance: synthetic` on each JSON object.

Do not invent or modify labels after they are authored. Regenerating a file is allowed only by running the matching script, which is the label source of truth.

Nothing in these files is Radware IP, customer traffic, or production telemetry.
