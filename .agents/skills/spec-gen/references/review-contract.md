# Candidate-bound review

Submission requires separate evidence, validation receipt and review artifacts.
A review records the protocol, candidate SHA-256, current target SHA-256,
`decision: approve`, actual reviewer, `field_evidence`,
`cross_field_dependencies` and `limitations`.

`field_evidence` must map every non-marker field to one or more indices in the
evidence `hits` array. The cited original text must support that field. Record
length coverage, conditional fields and positive-value combinations explicitly.
Use `agent:spec-gen` for agent review; never impersonate a human reviewer.
The tool checks hashes, source spans and mapping completeness, but cannot verify
human identity or understanding. A reviewer string is not a signature or a
substitute for user authorization.

Generate receipts with `validate`; never fabricate a successful receipt. Recheck
and review after changing the candidate, source files, catalog or engine.
`submit` without `--apply` only checks gates. `--apply` updates one registered
profile and saves `.cache/spec-gen/backups/<name>.<hash>`. It does not change
imports, service settings, datasets or Git. New profiles need source registration,
a public class, an independent parser and tests before using the admission tool.
