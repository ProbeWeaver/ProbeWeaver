# ProbeWeaver

Protocol modeling, field-level probe search and scanner assembly for the paper's
31 services, 32 mutation profiles and 113 implementation/configuration variants.
The two MQTT versions share one identification label.

## Repository layout

| Directory | Purpose |
| --- | --- |
| `core/` | Probe Search runtime: campaign scheduling, reinforcement learning field mutation, adaptive budgets, TCP/UDP observation, background-adjusted objectives, deduplication and candidate storage. Also provides shared corpus and coverage utilities. |
| `protocol/` | Field definitions, bounded profile interfaces, length encodings, source catalog and independent wire validation. `specs/` contains the 32 protocol mutation profiles. |
| `fingerprint/` | Response feature extraction, random-forest training support, Go model export and version extraction. `agent/` provides deterministic response analysis, evidence checks and rule validation tools used by the rule-generation skill. |
| `rag/` | Optional local embedding and vector retrieval support for operator-supplied protocol documents. |
| `scripts/` | Command-line tools for seed creation, background calibration, corpus preparation, skill-driven modeling and rule assembly, classifier training/export, candidate stability checks and probe selection. |
| `.agents/skills/` | Coding-agent workflows: `spec-gen/` implements Protocol Modeling; `rule-gen/` implements Scanner Assembly. These skills use the repository tools directly. |
| `Docker/` | Local experimental service definitions and startup scripts. `base/` contains shared base-image recipes; `services/` contains the selected implementations and synthetic configuration fixtures. |
| `PW_Scanner/` | The scanner, based on ZGrab2. `cmd/` contains executable entry points; `bin/` contains CLI orchestration; `modules/fuzzing/` sends probes and identifies responses; `lib/fingerprint/` contains the frozen identifiers. `scan.py` and `sequence.py` execute the ranked probe sequences. |
| `probes/` | The final eight TCP and three UDP probes, plus their sanitized local responses and redaction metadata. |

At the repository root, `main.py` starts the transport-separated search campaigns;
`config.py` controls search parameters; `services_config.py` defines local
endpoints and service groupings; and `environment.yaml` declares the
Python environment.

## Install and build

```bash
mamba env create -f environment.yaml
bash PW_Scanner/build.sh
```

Go is needed for the scanner and generated-rule validators. Docker Engine and
its Compose plugin are needed for the experimental services. PDF source
retrieval additionally uses `pdftotext`.

## Run the scanner

The fixed sequences and sanitized local responses are in `probes/`: eight TCP
probes and three UDP probes, executed in rank order.

```bash
mamba run -n protocol_fuzzer python PW_Scanner/scan.py --host 127.0.0.1 --port 24078 --transport tcp
```

Use the actual target port from `Docker/.env`. The wrapper stops on a service
result or sequence exhaustion and preserves ambiguous results. See
`PW_Scanner/README.md` for upstream attribution and execution details.

## Run a new local search

```bash
bash Docker/start.sh
mamba run -n protocol_fuzzer python scripts/create_seeds.py
mkdir -p .cache outputs/rewards
mamba run -n protocol_fuzzer python scripts/collect_background_controls.py --seeds-file seeds.txt --output outputs/controls.jsonl
mamba run -n protocol_fuzzer python scripts/calibrate_background.py fit --controls outputs/controls.jsonl --reward-root outputs/rewards --output .cache/background_profile.json
mamba run -n protocol_fuzzer python main.py
bash Docker/stop.sh
```

All related system parameters are configured in `config.py`.

## Skills

- `.agents/skills/spec-gen/SKILL.md`: Protocol Modeling with explicit protocol
  identity, source-bound retrieval, staged generation, independent wire checks
  and candidate-bound review/admission.
- `.agents/skills/rule-gen/SKILL.md`: Scanner Assembly with response analysis,
  source retrieval, bounded analysis execution, Go validation, echo exclusion,
  full-corpus admission and compilation into the service/member cascade.

The coding agent follows the skills directly. Supply approved documents at the paths in
`protocol/spec_sources.json`; missing or changed sources fail admission.
Lexical retrieval works without a model; vector retrieval is optional.

The assembly tools include `rule_pipeline.py` (prepare/validate/freeze),
`build_rule_training_corpus.py`, `train_tier2_rf.py`, `train_member_rf_corpus.py`,
`build_rule_bundle_provenance.py`, `reprobe_candidate_stability.py`, and
`build_full_deployment_artifact.py`. Use each script's `--help` for its inputs.
Full-cascade selection uses correctly identified service–implementation pairs
from banner and post-send responses to construct a complementary probe sequence.
