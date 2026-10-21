# PW Scanner

PW Scanner is based on **ZGrab2** (https://github.com/zmap/zgrab2).
It reuses ZGrab2's connection handling, TLS support, module framework and JSON
output. The upstream Go module/import paths and Apache-2.0 and ISC licenses are retained
in `go.mod` and `LICENSE`. The published executable is named `pw-scanner`.
Only the fuzzing module and its required runtime/identifier code are included.

From the repository root, run `bash PW_Scanner/build.sh`, then:

```bash
mamba run -n protocol_fuzzer python PW_Scanner/scan.py --host 127.0.0.1 --port 24078 --transport tcp
mamba run -n protocol_fuzzer python PW_Scanner/scan.py --host 127.0.0.1 --port 24014 --transport udp
```

Replace the port with the selected local service's published port. TCP first
attempts TLS; a handshake failure retries the same ranked probe once in
plaintext, then fixes that transport mode for subsequent probes. UDP is plain.
The ranked sequence stops at a service result or exhaustion. Results retain
ambiguity, response phases and actual application-write counters.

Identification uses service rules, then the frozen 44-feature RF, then generic
fallback rules. Member rules/RFs refine a confirmed service. The original
compiled model is retained rather than silently retrained; its historical
out-of-scope labels remain internal. A result containing LPD, SMTP or OpenVPN
is reported as unknown, matching the paper's scope policy. MQTT version
candidates remain explicit.

`go test ./...` checks the Go runtime. `cmd/identify` is a persistent offline
JSONL full-cascade classifier; build it with `go build -o /tmp/pw-identify
./cmd/identify` from this directory and pass `-rules rules.json`. Its inputs
contain bytes and phase metadata, never truth labels.
