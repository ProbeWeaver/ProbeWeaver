---
name: rule-gen
description: Generate and repair evidence-backed, multi-branch Go identification rules for PW Scanner at service and implementation levels. One service entry point may combine multiple response formats; implementation refinement runs only after service confirmation. Validate branch precision and full-function coverage against the current corpus, with fresh validation reported separately.
---

# Two-Tier Identification Rule Generator (Cluster → Member)

You generate **Go identification functions** at two granularities. Both are pure Go function
bodies; both are validated by the same Go harness. The two tiers are **nested**, not peers:

- **Tier 1 — Cluster (service) layer, the OUTERMOST gate.** One function per cluster
  (`type=code`). It returns `true` iff the response belongs to THIS service cluster, and
  discriminates it from ALL other clusters. The runtime runs cluster matching first.
- **Tier 2 — Member (implementation/version) layer, a NESTED BRANCH.** One function per
  member (`type=member_code`), scoped to ONE cluster. It returns `true` iff the response is
  THIS member, discriminating it from its SIBLING members. The runtime evaluates a cluster's
  member functions ONLY AFTER that cluster is confirmed — so a member function may assume it
  is already inside its cluster. Member matching is a refinement branch under the service
  match, never a substitute for it.

Think of the final generated code as: **outermost = service match; once the service is
confirmed, the member branch runs under that condition.** Your member body should read as
"this is the cluster, AND specifically this member" (see Tier 2 code structure).

You submit one PRIMARY function and optionally one FALLBACK function per target:
- Cluster: `{"type": "code", "code": "<body>"}` (one object per cluster).
- Member: `{"type": "member_code", "code": "<body>", "member": "<member>"}` (one object per
  member; `service` stays the cluster, `member` is the variant).

The deterministic exchange represents them as a 1–2 item bundle with roles
`primary` and optional `fallback`. Each function must independently pass the precision gate;
the OR union must pass full-construction atom recall and unique-response-identity coverage.
Do not split one unsafe broad rule into two rules to evade a gate.

**One function is one entry point, not one condition or one response shape.**
Inside that function, use as many evidence-backed `if`/`switch` branches as
needed for different message types, field combinations, normal/error replies,
handshake stages, encodings, or coalesced frames. The 1–2-function bundle limit
does not limit internal branches. Do not require one literal or offset value
to hold across every response when several legitimate formats exist.

## Multi-branch coverage workflow

1. Analyze the full positive set and negatives before choosing branches.
   Group response shapes by meaningful wire-format discriminators, not by
   endpoint address, response presence, or arbitrary per-packet identities.
2. For each group, establish response-side evidence and bounded parsing:
   framing, type, flags, lengths, field relations, and optional self-ID.
   Consult RAG/source documents for the relevant protocol version. A fixed
   seed layout is not the complete grammar of server responses.
3. Account for normal and error replies, optional properties, and stream
   coalescing where observed. Do not impose a short fixed length because it
   covers the most frequent shape. Conversely, do not accept arbitrary
   malformed/truncated bytes merely to raise recall.
4. Measure each branch against **all negative classes** and record its atom
   and unique-response coverage, including marginal coverage after earlier
   branches. A diagnostic branch may cover a small positive subset; it must
   still meet the unchanged precision and echo requirements. Diagnostic
   measurements are not admission of a low-recall standalone rule.
5. Combine branches into the function and run the complete Go/echo validator.
   The union must meet the configured full-corpus atom-recall and identity
   coverage gates. Include branch overlap and residual uncovered shapes in
   the review artifact. Never silently change gates or the denominator.
6. Before `declare_no_invariant`, distinguish missing branches, conflicting
   response bytes, non-identifying observations, and missing samples. Record
   the residual evidence and attempted branch families. A rejected candidate
   is not proof that no service rule exists. Keep useful partial candidates
   explicitly unadmitted; deploying them needs a separate agreed policy.

An invariant means a stable **conditional constraint** in its branch, or the
union of such constraints—not necessarily a globally constant byte string.
Multiple branches cannot resolve genuinely identical cross-service replies.
Generic HTTP errors, blank keepalives, and reflected input must not become
claims about a specific service simply because one benchmark label emitted
them. No-response targets need evidence before admission; do not silently
import historical rules as if validated by the new experiment.

## Identification-equivalence groups

Probe clusters and identification clusters are different namespaces. If response evidence cannot
distinguish several probe labels (currently `mqttv311` and `mqttv50`), generate one rule for the
canonical identification cluster (`mqtt`). Runtime expands it into the full candidate set
(`[mqttv311, mqttv50]`) and marks the result ambiguous. Never copy the same rule under several labels
or choose one label alphabetically. Cross-group multi-matches remain false positives, not legitimate
ambiguity.

## The Go contract (rule form — BOTH tiers)

`code` is a **function body** — pure statements pasted inside `func match(resp []byte) bool { ... }`.
Rules (identical for cluster and member bodies):

- Input: `resp []byte` (the server response). **Must `return bool`** on every path (Go enforces this).
- **No `import`, no `package`, no `func` declarations.** The harness pre-imports what you need.
- You may freely use: `len(resp)`, byte indexing `resp[i]`, slicing `resp[a:b]`, arithmetic & bitwise
  ops, comparisons, `if`/`for`/`switch`. Pre-imported helpers:
  - `bytes.Contains(resp, []byte("MongoDB"))` — substring (ASCII self-ID in the body).
  - `bytes.HasPrefix(resp, []byte("SSH-2.0-dropbear_"))` — anchored prefix (great for banners).
  - `binary.BigEndian.Uint16(resp[2:4])` / `Uint32` / `Uint64` — read a big-endian field.
- **Panics are caught** (an out-of-range index or bad slice counts as non-match, i.e. `false`). So
  **guard length/index first**: `if len(resp) < 48 { return false }` before reading `resp[0]`.

Examples (complete bodies):

```go
// Cluster — ASCII self-ID (MongoDB replying to an HTTP probe with an error naming itself)
return bytes.Contains(resp, []byte("MongoDB"))
```
```go
// Cluster — binary structure: NTP response — length gate + mode bit-field (multi-field AND)
if len(resp) < 48 {
    return false
}
return resp[0]&0x07 == 0x04   // low 3 bits = mode; 4 = server
```
```go
// Member (within ssh) — banner substring: this member IS dropbear (version literal ALLOWED here)
return bytes.HasPrefix(resp, []byte("SSH-2.0-dropbear_"))
```
```go
// Member (within modbus) — structural offset: byte at offset 10 separates this member from siblings
if len(resp) < 13 {
    return false
}
return resp[10] == 0x02 && resp[12] == 0x02
```

## Tier 1 — Cluster (service) rules (outermost)

Objective: **one Go function per cluster** that matches this cluster's responses and rejects all
other clusters. Prefer a Go function body — it is the only rule form you submit. A function can
express anything 4-form rules (pattern/magic/offset/mask) cannot: multi-field AND, length gates,
length-relative offsets, TLV walks.

Procedure (cluster):
1. Read the top-K hex/text + counts. Recognize the protocol and shape distribution.
2. Call `analyze` (whole set). Its findings suggest the stable bytes/bit-fields/substrings to encode.
3. If binary or structural, take the **ASCII path** (`analyze(mode="substrings")` / `text=` preview
   for an embedded self-ID token) or the **Structural path** (`rag` for the response format, then
   `run_code` to confirm a field value is constant in this cluster and discriminates from negatives).
   Cross-protocol polite errors (a shape starting `HTTP/`) often carry a self-ID string in the body.
4. Build and validate the branch coverage matrix and combined Go body as above.
   Inspect residual shapes before terminating via `submit_rules` or
   `declare_no_invariant`.

**Service rules must generalize across the supported implementations/versions.**
Different branches may handle different documented response formats; one
branch need not match every implementation. Drop version-specific literals
(e.g. `OpenSSH_8.9`) at the cluster tier. Version-independent self-ID evidence
may contribute a branch, but must not substitute for reviewing other formats.

## Tier 2 — Member (implementation/version) rules (nested branch)

Objective: **one Go function per member** that matches the TARGET member's responses and rejects its
SIBLING members' responses. Inputs you receive in member mode: the cluster name, the target member,
the target member's responses (`pos`), and the SIBLING members' responses (`neg`, keyed by member name).

Member matching runs only after the cluster is confirmed, so **do NOT re-derive the cluster gate from
scratch** — you may assume the response is already in-cluster. Your job is the member discriminator.

**Discrimination strategies, in order of reliability** (validated by re-probing — see the experiment
report; the lower ones are fragile):

1. **Banner / self-identification string** (text protocols embed product names). Most reliable — the
   string is present regardless of probe. Encode as `bytes.HasPrefix` / `bytes.Contains`. Examples:
   `SSH-2.0-dropbear_` vs `SSH-2.0-OpenSSH_`; `Server: nginx` vs `Server: Apache`; `220 ProFTPD` vs
   `220 vsFTPd`. **Version/product literals (`OpenSSH_8.9`, `dropbear_2024`) are ALLOWED here and are
   usually the BEST discriminators — do NOT drop them.**

2. **Structural offset** (binary protocols). A byte at a fixed offset that is CONSTANT across the
   target member's responses AND differs from siblings. Use `analyze`/`run_code` (with sibling `neg`)
   to find it; encode as `resp[off] == 0x..`. **AND several offsets** for robustness (a single byte
   can coincide by chance). Always guard length first. This is the primary lever for binary members
   (modbus, mqtt, ntp, memcached, snmp, telnet option bytes, …).

3. **Probe-conditional content** (advanced). Some members differ ONLY on a specific probe's response
   (e.g. mongodb: byte at offset 4 is `89`/`8e`/`93` across baseline/mongo5/mongo6 — but only on the
   discriminating probe). If no offset is constant across ALL of the member's responses, compare
   responses **per probe** to find a probe where the members differ, then write the byte condition.
   This is real but rarer; confirm with `run_code` which probe separates them.

**DO NOT use "who responds" (probe-differential) as a discriminator.** Re-probing proved that "probe X
triggers member A but not B" is almost always a high-concurrency / short-timeout packet-drop artifact,
not protocol behavior. Member rules must be **content-based** (read response bytes), never trigger-based.

**Member code structure.** Each member body should read as "this is the cluster, AND specifically this
member." Concretely:
- Open with a length/bounds guard: `if len(resp) < N { return false }`.
- The member discriminator often **subsumes** the cluster gate (e.g. `SSH-2.0-dropbear_` already
  implies `SSH-`). When it does, you need not repeat the gate. When it does not (pure binary struct),
  you MAY prepend the cluster signature as an AND-condition for self-containment — it is redundant at
  runtime (the engine already scoped by cluster) but makes the body self-documenting.
- AND the member-specific conditions within each branch; OR alternative
  response formats. A failed branch falls through to the next branch, and
  the function returns `false` only when no branch matches.

If a member has no byte that separates it from siblings, `declare_no_invariant` — an honest outcome
(the member RF may still handle it, or that member is simply not byte-distinguishable). Do not
hand-fabricate constants.

## Inputs you receive

- The **cluster name** (and, in member mode, the **target member** + sibling member names) and total
  response counts.
- **Top-K response shapes** as hex (first 64 bytes of each) with frequency counts, **plus a decoded
  ASCII `text=` preview** (first 256 bytes; non-printable shown as `.`; suppressed for binary
  protocols). You MAY read these to recognize protocols/banners/magic with world knowledge (e.g.
  `5353482d` = `SSH-`, HTTP status lines, AMQP `AMQP\x00`). The `text=` preview is especially useful
  for **self-identification strings in the body** (a MongoDB server replying to HTTP with "...trying
  to access MongoDB over HTTP...").

## HARD RULES (non-negotiable)

1. **You may READ the hex/text to recognize a protocol** — world knowledge is useful for hypotheses.
2. **The preview is a sample, not ground truth.** Never transcribe offsets/values straight from the
   preview into a rule. Every constant in your Go body MUST be confirmed against the FULL dataset by
   `analyze`/`run_code`/`validate`. Do not hand-fabricate byte values.
3. **Every submitted function is re-validated server-side by the Go harness.** A cluster function is
   checked against this cluster's full construction positives (atom recall + unique response identity
   coverage) and all other identification clusters' negatives. A member function is checked against
   the target member's full construction responses and the
   SIBLING members' negatives (precision). A function that false-matches another cluster/member, or
   covers too little of the construction set, is rejected with a reason — fix and resubmit, or declare no
   invariant. **You cannot pass by extracting a structure from RAG alone — the function must match the
   ACTUAL responses.** Construction metrics are in-sample; the out-of-sample claim comes only from a
   frozen, probe-family-disjoint fresh validation round.
4. **Version-literal rule is DUAL:**
   - **Cluster tier:** conditional constraints must generalize across supported
     implementations/versions; different formats may have different branches. **Drop**
     version-specific literals (e.g. `OpenSSH_8.9`) as service discriminators.
   - **Member tier:** version/product literals (`OpenSSH_8.9`, `dropbear_2024`, `mongo5`) **ARE the
     signal** — keep them; they are usually the best member discriminators.
5. **Probe-echo guard.** A rule constant overlapping construction probes or packet-derived response
   spans is rejected unless its justification cites an evidence ID present in deterministic findings
   or bound protocol-document provenance. Free-form prose alone cannot bypass this guard.

## Tools

- **`analyze(subset?, mode?)`** — deterministic analyzer. Finds constant prefix / offset-magic /
  bitmask, AND **discriminating substrings** (body strings present in this group and absent from all
  negatives). In member mode the "negatives" are sibling members. Use its output to **inform your Go
  body** (e.g. "offset 0 mask 07 value 04" → `resp[0]&0x07==0x04`). `mode`: `all` (default) /
  `deterministic` / `substrings`. **Call this first.** `analyze` only scans offsets 0-7; for deeper
  fields use `rag`+`run_code`.
- **`rag(task)`** — retrieve response-side protocol documentation (header layout, field offsets/types,
  magic bytes, packed bit-fields). Primary source for the **structural-parsing** path on binary
  responses.
- **`run_code(code)`** — sandboxed Python. Write `def run(pos, neg)` returning a JSON object. Use to
  measure field-value distributions, byte histograms, or how well a candidate separates positives from
  negatives (e.g. "what fraction of pos have `resp[10]==0x02`?"; for member mode, "which offset
  separates the target member from siblings?"). (No `import`, no dunder, no `open`/`eval`/`exec`/`getattr`.)
- **`validate(rule)`** — validate ONE Go body (`{type:"code"/"member_code", code:"<body>"}`). Runs the
  Go harness on construction positives/negatives and returns `{ok, reason, recall}`.
  This is not a fresh held-out result. **Iterate here** before submitting.
- **`submit_rules(rules, rationale)`** — **terminate** by submitting
  `[{type:"code"/"member_code", code:"<body>", ...}]`.
- **`declare_no_invariant(reason)`** — **terminate** by honestly giving up. Some clusters/members have
  no discriminating invariant — a correct outcome, not a failure.

## Procedure (member tier — follow this recipe)

1. Confirm the cluster context (given). Identify the target member and its siblings.
2. Read the target member's top-K hex/text + the siblings' shapes. Recognize what differs.
3. Pick a strategy by reliability:
   - **Banner?** → `analyze(mode="substrings")` or `text=` preview for a product/version string unique
     to this member. Encode as `bytes.Contains`/`HasPrefix`. (Version literals allowed.)
   - **Binary struct?** → `run_code` to scan offsets for a byte constant in the target member that is
     absent from siblings; AND 2-4 such offsets. Guard length first.
   - **No global-constant offset?** → consider **probe-conditional content**: `run_code` per probe to
     find a probe where members differ, then write the byte condition.
   - **Never** use who-responds.
4. Write the Go body (length guard + discriminator), `validate`. Read `{recall, reason}`:
   - low recall → broaden (the member may have multiple shapes; OR them) or pick a different offset;
   - false-match a sibling (`false match in sibling class`) → tighten (add an AND condition that excludes it);
   - compile error → fix Go syntax.
   Stop repeating the same hypothesis after two identical rejections. Before
   ending the target, inspect uncovered shape families: a genuinely different,
   evidence-backed branch is a new hypothesis, not a reason to weaken gates.
   Keep the overall per-target budget bounded; record remaining gaps if it is exhausted.
5. Terminate via `submit_rules([{type:"member_code", code:"<body>"}], rationale)` or
   `declare_no_invariant`. Never leave the task open.

## Budget

At most ~24 tool calls per cluster (Tier 1) or per (cluster, member) pair (Tier 2). Be deliberate:
prefer `analyze` → `rag`/`run_code` → write body → `validate` (iterate) → `submit`, over open-ended
exploration.

## Codex usage

The same tools are invokable as a CLI for direct/manual runs:
`mamba run -n protocol_fuzzer python -m fingerprint.agent.tools <cmd>` with subcommand in `{analyze, rag, run_code, validate,
submit_rules, declare_no_invariant}`, reading JSON from stdin and writing JSON to stdout. For
`validate`/`submit_rules` of a code rule, feed `{"rule":{"type":"code","code":"<body>"}}` (or
`type:"member_code"`) plus held/neg hex arrays; in member mode `neg` is keyed by sibling member name.

## Reproducible skill-driven exchange

Use `scripts/rule_pipeline.py prepare --help`, then `validate --help` and
`freeze --help`. These commands prepare the complete phase-aware corpus,
validate each proposed bundle and freeze only a report-bound accepted draft.
The coding agent follows this skill directly. There is no embedded LLM loop.
`fingerprint.agent.tools` also exposes `echo_check` and `select_cover`.
The RAG command uses source-bound local lexical retrieval; inspect the cited
source spans before writing a rule. Optional vector retrieval is available
through `scripts/spec_agent.py rag --backend vector`. Documents are not bundled.

After freezing approved rules, use `scripts/deploy_code_rules.py` and
`scripts/deploy_member_code_rules.py` to generate the Go registries in
`PW_Scanner/lib/fingerprint`, then build and test the scanner. Train/export
the paper service classifier with `scripts/train_tier2_rf.py`, implementation
classifiers with `scripts/train_member_rf_corpus.py`, and export them through
`fingerprint/export_to_go.py`. The general `mamba run -n protocol_fuzzer python -m fingerprint` entry point
is also available.
Use `scripts/build_full_deployment_artifact.py` for full-cascade selection,
with a bound corpus, frozen rules, RF manifest and stability observations.
`evaluate_distinguishability.py` is a rules-only diagnostic; do not describe
its output as full-classifier coverage. `select_packets_split_transport.py`
provides the shared weighted selector.
The bundled eleven probes and frozen identifiers can be used without training.
Their sanitized response samples are examples, not the full training corpus.
