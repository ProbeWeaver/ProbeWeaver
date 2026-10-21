"""Ranked probe execution with the paper's first-probe TLS/plaintext policy."""

from __future__ import annotations

import hashlib, json, os, re, subprocess, time

from pathlib import Path

from typing import Any, Mapping

from datetime import datetime, timezone

def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

class E1ToolError(RuntimeError):
    """Invalid input, adapter failure, or unsafe execution condition."""

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _safe_filename(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in value)

def _run(
    command: Sequence[str], *, timeout: Optional[float], stdin: Optional[str] = None,
) -> tuple[int, bytes, bytes, float, bool]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(command), input=stdin.encode() if stdin is not None else None,
            capture_output=True, timeout=timeout, check=False)
        return (proc.returncode, proc.stdout, proc.stderr,
                time.monotonic() - started, False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        return (124, stdout, stderr, time.monotonic() - started, True)

def _raw_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path.resolve()), "exists": False,
                "size_bytes": 0, "sha256": ""}
    return {
        "path": str(path.resolve()),
        "exists": True,
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }

def _endpoint_record(target: Mapping[str, Any], tool: str, mode: str) -> dict:
    endpoint = target["endpoint"]
    return {
        "target_id": target["target_id"],
        "endpoint": {
            "ip": endpoint["ip"],
            "port": endpoint["port"],
            "transport": endpoint["transport"],
        },
        "tool": tool,
        "mode": mode,
        "outcome": "unknown",
        "raw_labels": [],
        "security_labels": [],
        "raw_prediction": {},
        "cost": {
            "application_payloads": 0,
            "connections": 0,
            "payload_bytes": 0,
            "wall_seconds": 0.0,
        },
        "return_code": None,
        "timed_out": False,
        "raw_files": [],
        "command": [],
        "stderr_sha256": "",
    }

def load_ranked_payloads(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    rows = document.get("selected_packets") if isinstance(document, dict) else document
    if not isinstance(rows, list) or not rows:
        raise E1ToolError(f"probe set {path} contains no selected packets")
    payloads = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise E1ToolError("selected packet must be an object")
        packet_hex = str(row.get("packet_hex") or "").strip().lower()
        try:
            packet = bytes.fromhex(packet_hex)
        except ValueError as exc:
            raise E1ToolError("selected packet has invalid packet_hex") from exc
        rank = int(row.get("rank", index))
        payloads.append({"rank": rank, "packet_hex": packet_hex,
                         "size_bytes": len(packet)})
    ranks = [row["rank"] for row in payloads]
    if len(ranks) != len(set(ranks)):
        raise E1ToolError("probe set has duplicate ranks")
    return sorted(payloads, key=lambda row: row["rank"])

def _parse_zgrab_jsonl(data: bytes) -> dict[str, Any]:
    rows = []
    labels: set[str] = set()
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        rows.append(row)
        result = (row.get("data", {}).get("fuzzing", {}).get("result") or {})
        candidates = result.get("candidates") or []
        for candidate in candidates:
            if str(candidate or ""):
                labels.add(str(candidate))
        if not candidates:
            for match in result.get("matches") or []:
                if isinstance(match, dict) and str(match.get("service") or ""):
                    labels.add(str(match["service"]))
            if not labels and str(result.get("service") or ""):
                labels.add(str(result["service"]))
    return {"labels": sorted(labels), "records": rows}

def run_ours_target(
    target: Mapping[str, Any], *, binary: str | Path, rules: str | Path,
    probe_set: str | Path, raw_dir: str | Path, timeout_seconds: float,
    process_timeout: float, use_ml: bool,
) -> dict[str, Any]:
    record = _endpoint_record(target, "ours", "frozen_ranked_early_stop")
    endpoint = target["endpoint"]
    payloads = load_ranked_payloads(probe_set)
    target_dir = Path(raw_dir) / _safe_filename(target["target_id"])
    target_dir.mkdir(parents=True, exist_ok=True)
    input_path = target_dir / "target.txt"
    input_path.write_text(endpoint["ip"] + "\n", encoding="utf-8")
    all_rows: list[dict[str, Any]] = []
    all_labels: set[str] = set()
    raw_files = []
    commands = []
    total_wall = 0.0
    sent = 0
    payload_bytes = 0
    last_rc = 0
    any_timeout = False
    connections = 0
    tls_mode = 'undetermined' if endpoint['transport'] == 'tcp' else 'plain'
    security_labels: set[str] = set()
    execution_error = False
    # The first payload also negotiates transport mode. A handshake failure
    # retries that SAME payload on a fresh plaintext connection exactly once.
    pending = list(payloads)
    while pending:
        payload = pending.pop(0)
        use_tls = tls_mode != 'plain'
        attempt_mode = 'tls' if use_tls else 'plain'
        raw_path = target_dir / f"rank_{payload['rank']:04d}_{attempt_mode}.jsonl"
        command = [str(binary), "-s", "1", "-f", str(input_path),
                   "-o", str(raw_path), "fuzzing", "-p",
                   str(endpoint["port"]), "--payload", payload["packet_hex"],
                   "--rules", str(rules), "-t", f"{timeout_seconds}s"]
        if use_ml:
            command.append("--use-ml")
        if endpoint["transport"] == "udp":
            command.append("--udp")
        elif use_tls:
            command.append('--tls')
        rc, stdout, stderr, elapsed, timed_out = _run(
            command, timeout=process_timeout)
        total_wall += elapsed
        last_rc = rc
        any_timeout = any_timeout or timed_out
        data = raw_path.read_bytes() if raw_path.exists() else stdout
        if not raw_path.exists():
            raw_path.write_bytes(data)
        parsed = _parse_zgrab_jsonl(data)
        all_rows.extend(parsed["records"])
        security_labels.update(set(parsed['labels']) & {'tls', 'ssl'})
        all_labels.update(set(parsed['labels']) - {'tls', 'ssl'})
        raw_files.append(_raw_metadata(raw_path))
        commands.append({"rank": payload["rank"], "command": command,
                         "transport_mode": attempt_mode,
                         "return_code": rc, "timed_out": timed_out,
                         "stderr_sha256": _sha256_bytes(stderr)})
        # Do not infer sends from process launches, TLS records or pcap segments.
        scan = (parsed['records'][0].get('data', {}).get('fuzzing', {})
                if len(parsed['records']) == 1 else {})
        facts = scan.get('result') or {}
        fields = ('application_payloads', 'application_payload_bytes', 'connections_established')
        if (timed_out or rc != 0 or any(type(facts.get(k)) is not int or facts[k] < 0 for k in fields)):
            execution_error = True
            break
        sent += facts['application_payloads']
        payload_bytes += facts['application_payload_bytes']
        connections += facts['connections_established']
        handshake = facts.get('tls_handshake_status')
        if tls_mode == 'undetermined':
            if handshake == 'failed' and str(scan.get('error') or '').startswith('TLS handshake failed:'):
                tls_mode = 'plain'
                pending.insert(0, payload)
                continue
            if handshake == 'succeeded':
                tls_mode = 'tls'
            elif handshake == 'not_attempted' and str(scan.get('error') or '').startswith('error establishing connection:'):
                # An unreachable endpoint is an ordinary unknown result, not
                # a broken scanner and not evidence for choosing plaintext.
                break
            else:
                # Connection/setup failure is not evidence of plaintext or TLS.
                execution_error = True
                break
        elif tls_mode == 'tls' and handshake != 'succeeded':
            # Keep the endpoint's decision; never silently switch later probes.
            continue
        if all_labels:
            break
    outcome = "identified" if all_labels else "unknown"
    if any_timeout and not all_rows:
        outcome = "timeout"
    elif last_rc != 0 and not all_rows:
        outcome = "tool_error"
    if execution_error:
        outcome = 'timeout' if any_timeout else 'tool_error'
    record.update({
        "outcome": outcome,
        "raw_labels": sorted(all_labels),
        "security_labels": sorted(security_labels),
        "tls_policy": "first_probe_tls_then_fixed_mode_v1",
        "selected_transport_mode": tls_mode,
        "raw_prediction": {"records": all_rows},
        "return_code": last_rc,
        "timed_out": any_timeout,
        "command": commands,
        "raw_files": raw_files,
    })
    record["cost"].update({
        "application_payloads": None if execution_error else sent,
        "connections": connections,
        "payload_bytes": None if execution_error else payload_bytes,
        "application_count_complete": not execution_error,
        "wall_seconds": total_wall,
        "cost_note": "scanner write counters; TLS handshake excluded; partial writes count as one probe; incomplete observations are null",
    })
    return record
