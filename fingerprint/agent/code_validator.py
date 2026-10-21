"""Compile and execute generated Go response matchers against complete positive/negative sets. Enforce per-rule precision and union recall/unique-identity coverage. Guard panics and timeouts; the supplied function body must return a boolean."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Tuple

_HARNESS_GO = """package main

import (
\t"bytes"
\t"encoding/binary"
\t"encoding/hex"
\t"encoding/json"
\t"fmt"
\t"os"
)

// Response identification and coverage validation.
func match(resp []byte) bool {
{BODY}
}

// Response identification and coverage validation.
func safeMatch(resp []byte) (r bool) {
\tdefer func() { recover() }()
\treturn match(resp)
}

// Response identification and coverage validation.
var (
\t_ = bytes.Compare
\t_ = binary.BigEndian
)

func main() {
\traw, err := os.ReadFile(os.Args[1])
\tif err != nil {
\t\tfmt.Println(`{"error":"read samples failed"}`)
\t\treturn
\t}
\tvar s struct {
\t\tHeld         []string            `json:"held"`
\t\tHeldDistinct []string            `json:"held_distinct"`
\t\tNeg          map[string][]string `json:"neg"`
\t}
\tif err := json.Unmarshal(raw, &s); err != nil {
\t\tfmt.Println(`{"error":"parse samples failed"}`)
\t\treturn
\t}
\tdecode := func(h string) []byte {
\t\tb, e := hex.DecodeString(h)
\t\tif e != nil {
\t\t\treturn nil
\t\t}
\t\treturn b
\t}
\thits := 0
\tfor _, h := range s.Held {
\t\tif safeMatch(decode(h)) {
\t\t\thits++
\t\t}
\t}
\tn := len(s.Held)
\tif n == 0 {
\t\tn = 1
\t}
\t// Response identification and coverage validation.
\tdistinctHits := 0
\tfor _, h := range s.HeldDistinct {
\t\tif safeMatch(decode(h)) {
\t\t\tdistinctHits++
\t\t}
\t}
\tnd := len(s.HeldDistinct)
\tif nd == 0 {
\t\tnd = 1
\t}
\tfp := map[string]float64{}
\tfor c, arr := range s.Neg {
\t\tif len(arr) == 0 {
\t\t\tfp[c] = 0
\t\t\tcontinue
\t\t}
\t\tf := 0
\t\tfor _, h := range arr {
\t\t\tif safeMatch(decode(h)) {
\t\t\t\tf++
\t\t\t}
\t\t}
\t\tfp[c] = float64(f) / float64(len(arr))
\t}
\tout, _ := json.Marshal(map[string]interface{}{
\t\t"recall":          float64(hits) / float64(n),
\t\t"distinct_recall": float64(distinctHits) / float64(nd),
\t\t"fp":              fp,
\t})
\tfmt.Println(string(out))
}
"""

_GO_MOD = "module harness\n\ngo 1.21\n"

def validate_code(body: str, held: List[bytes], neg: Dict[str, List[bytes]],
                  min_recall: float, tau_other: float, timeout: float = 10.0,
                  go_bin: str = "go", held_distinct: List[bytes] = None,
                  min_identity_coverage: float = None
                  ) -> Tuple[bool, str, float, float]:
    """Compile and validate a Go matcher; return precision status, recall and identity coverage."""
    if not body or not body.strip():
        return False, "empty Go function body", 0.0, 0.0
    if re.search(r"\bimport\b", body):
        return False, "imports are forbidden; bytes/binary are pre-imported", 0.0, 0.0

    if held_distinct is None:
        held_distinct = [bytes.fromhex(h) for h in sorted({b.hex() for b in held})]

    indented = "\n".join(("\t" + line) if line.strip() else line
                         for line in body.splitlines())
    src = _HARNESS_GO.replace("{BODY}", indented)
    samples = {
        "held": [b.hex() for b in held],
        "held_distinct": [b.hex() for b in held_distinct],
        "neg": {c: [x.hex() for x in xs] for c, xs in neg.items()},
    }

    d = tempfile.mkdtemp(prefix="code_harness_")
    try:
        with open(os.path.join(d, "go.mod"), "w") as f:
            f.write(_GO_MOD)
        with open(os.path.join(d, "main.go"), "w") as f:
            f.write(src)
        samples_path = os.path.join(d, "samples.json")
        with open(samples_path, "w") as f:
            json.dump(samples, f)

        try:
            r = subprocess.run([go_bin, "run", ".", samples_path], cwd=d,
                               capture_output=True, timeout=timeout, text=True)
        except subprocess.TimeoutExpired:
            return False, f"Go harness timed out ({timeout:g}s; possible unbounded loop)", 0.0, 0.0
        except FileNotFoundError:
            return False, f"Go executable unavailable ({go_bin}）", 0.0, 0.0

        if r.returncode != 0:
            err = (r.stderr or "").strip().splitlines()
            tail = err[-1] if err else (r.stderr or "")[:300]
            return False, f"Go compilation/execution failed: {tail[:300]}", 0.0, 0.0

        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if not lines:
            return False, "harness produced no output", 0.0, 0.0
        try:
            out = json.loads(lines[-1])
        except json.JSONDecodeError:
            return False, f"harness output parsing failed: {lines[-1][:200]}", 0.0, 0.0
        if "error" in out:
            return False, f"harness error: {out['error']}", 0.0, 0.0

        recall = float(out.get("recall", 0.0))
        coverage = float(out.get("distinct_recall", 0.0))
        fp = out.get("fp", {}) or {}
        bad = sorted((c, rate) for c, rate in fp.items() if rate > tau_other)
        if bad:
            c, rate = bad[0]
            return (False,
                    f"false matches in service '{c}' rate {rate:.2f} > τ_other {tau_other}",
                    recall, coverage)
        if recall < min_recall:
            return False, f"recall {recall:.2f} < min_recall {min_recall}", recall, coverage
        if min_identity_coverage is not None \
                and coverage < float(min_identity_coverage):
            return (False,
                    f"identity coverage {coverage:.2f} < min_identity_coverage "
                    f"{float(min_identity_coverage):g} (too many unique response shapes are uncovered)",
                    recall, coverage)
        return True, "ok", recall, coverage
    finally:
        shutil.rmtree(d, ignore_errors=True)

def validate_code_bundle(
    bodies: List[str], held: List[bytes], neg: Dict[str, List[bytes]],
    min_recall: float, tau_other: float, timeout: float = 10.0,
    go_bin: str = "go", held_distinct: List[bytes] = None,
    min_identity_coverage: float = None,
) -> Tuple[bool, str, float, float, List[dict]]:
    """Check each function's precision and the one/two-function union's coverage."""
    if not isinstance(bodies, list) or not 1 <= len(bodies) <= 2:
        return False, "rule bundle must contain 1 or 2 Go bodies", 0.0, 0.0, []
    if len({body.strip() for body in bodies if isinstance(body, str)}) != len(bodies):
        return False, "rule bundle contains duplicate Go bodies", 0.0, 0.0, []
    details: List[dict] = []
    for index, body in enumerate(bodies):
        ok, reason, recall, coverage = validate_code(
            body, held, neg, 0.0, tau_other, timeout=timeout, go_bin=go_bin,
            held_distinct=held_distinct, min_identity_coverage=None)
        if not ok:
            return (False, f"rule[{index}] precision/compile gate failed: {reason}",
                    0.0, 0.0, details)
        if recall <= 0.0:
            return (False, f"rule[{index}] matches no positive response",
                    0.0, 0.0, details)
        details.append({"index": index, "recall": recall,
                        "identity_coverage": coverage})

    combined_lines: List[str] = []
    for body in bodies:
        combined_lines.append("if func() bool {")
        combined_lines.extend("\t" + line for line in body.splitlines())
        combined_lines.append("}() { return true }")
    combined_lines.append("return false")
    combined = "\n".join(combined_lines)
    ok, reason, recall, coverage = validate_code(
        combined, held, neg, min_recall, tau_other, timeout=timeout,
        go_bin=go_bin, held_distinct=held_distinct,
        min_identity_coverage=min_identity_coverage)
    return ok, reason, recall, coverage, details

def match_rates(body: str, clusters: Dict[str, List[bytes]],
                timeout: float = 10.0, go_bin: str = "go") -> Dict[str, float]:
    """Compile a matcher and measure its rate over each complete response class."""
    if not body or not body.strip() or re.search(r"\bimport\b", body):
        return {"_error": "empty body or forbidden import"}
    indented = "\n".join(("\t" + line) if line.strip() else line for line in body.splitlines())
    src = _HARNESS_GO.replace("{BODY}", indented)
    samples = {"held": [], "held_distinct": [],
               "neg": {c: [x.hex() for x in xs] for c, xs in clusters.items()}}
    d = tempfile.mkdtemp(prefix="code_rates_")
    try:
        with open(os.path.join(d, "go.mod"), "w") as f:
            f.write(_GO_MOD)
        with open(os.path.join(d, "main.go"), "w") as f:
            f.write(src)
        sp = os.path.join(d, "samples.json")
        with open(sp, "w") as f:
            json.dump(samples, f)
        try:
            r = subprocess.run([go_bin, "run", ".", sp], cwd=d,
                               capture_output=True, timeout=timeout, text=True)
        except subprocess.TimeoutExpired:
            return {"_error": f"timed out ({timeout:g}s）"}
        except FileNotFoundError:
            return {"_error": f"Go executable unavailable ({go_bin}）"}
        if r.returncode != 0:
            return {"_error": "Go compilation/execution failed: " + (r.stderr or "")[:200]}
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if not lines:
            return {"_error": "no output"}
        try:
            out = json.loads(lines[-1])
        except json.JSONDecodeError:
            return {"_error": "output parsing failed"}
        return out.get("fp", {}) or {}
    finally:
        shutil.rmtree(d, ignore_errors=True)
