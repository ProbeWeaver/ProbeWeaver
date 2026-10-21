#!/usr/bin/env python3
"""Collect the fixed background-control probe suite.

This is the only script in the current pipeline that performs control network I/O.
It writes one atomic JSONL artifact containing 16 connect-only/zero-length
controls, 64 deterministic random payloads, and 16 deterministic shuffled-seed
payloads per transport.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import socket
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from core.clustering import cluster_of
from core.service_tester import ServiceResponse, ServiceTester

RANDOM_LENGTHS = (8, 16, 32, 64, 128, 256)

def load_seed_packets(path: Path) -> List[bytes]:
    packets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        token = line.strip().split(",", 1)[0]
        if not token or token.startswith("#"):
            continue
        try:
            packets.append(bytes.fromhex(token))
        except ValueError:
            continue
    if not packets:
        raise ValueError(f"no valid hexadecimal seeds in {path}")
    return packets

def deterministic_payloads(
    seeds: Sequence[bytes], *, random_seed: int = 20260825
) -> Dict[str, List[bytes]]:
    if not seeds:
        raise ValueError("at least one seed is required")
    rng = random.Random(random_seed)
    random_payloads = [
        rng.randbytes(RANDOM_LENGTHS[i % len(RANDOM_LENGTHS)])
        for i in range(64)
    ]
    shuffled = []
    for i in range(16):
        raw = bytearray(seeds[i % len(seeds)])
        local = random.Random(random_seed + 10_000 + i)
        local.shuffle(raw)
        shuffled.append(bytes(raw))
    return {"random": random_payloads, "shuffled": shuffled}

def _transport_members(services: Mapping[str, tuple], transport: str) -> Dict[str, tuple]:
    """Project registry entries onto one concrete transport.

    ``ServiceTester`` consumes normalized ``(host, port, transport)`` tuples.
    A member declared as ``both`` must therefore become ``tcp`` in the TCP
    control campaign and ``udp`` in the UDP campaign.
    """
    result = {}
    for name, endpoint in services.items():
        if isinstance(endpoint, dict):
            host = str(endpoint.get("host", "127.0.0.1"))
            port = int(endpoint.get("port", 0))
            member_transport = str(endpoint.get("protocol", "tcp")).lower()
        else:
            values = tuple(endpoint)
            host = str(values[0])
            port = int(values[1])
            member_transport = str(values[2] if len(values) > 2 else "tcp").lower()
        if member_transport in (transport, "both"):
            result[name] = (host, port, transport)
    return result

def _connect_only_one(name: str, endpoint: tuple, timeout: float) -> ServiceResponse | None:
    if isinstance(endpoint, dict):
        host, port = endpoint.get("host", "127.0.0.1"), endpoint.get("port", 0)
    else:
        host, port = endpoint[:2]
    start = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(8192)
            if not banner:
                return None
            latency = (time.time() - start) * 1000.0
            return ServiceResponse(
                service_name=name,
                response_bytes=banner,
                latency_ms=latency,
                timestamp=time.time(),
                response_phase="pre_payload_banner",
                banner_bytes=banner,
                banner_latency_ms=latency,
            )
    except OSError:
        return None

def connect_only_parallel(
    services: Mapping[str, tuple], *, timeout: float, workers: int
) -> List[ServiceResponse]:
    responses = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_connect_only_one, name, endpoint, timeout): name
            for name, endpoint in services.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                responses.append(result)
    return responses

def response_record(response: ServiceResponse) -> dict:
    return {
        "service": response.service_name,
        "cluster": cluster_of(response.service_name),
        "response_phase": response.response_phase,
        "banner_hex": response.banner_bytes.hex(),
        "response_hex": response.payload_bytes.hex(),
        "banner_latency_ms": response.banner_latency_ms,
        "payload_latency_ms": response.payload_latency_ms,
    }

def collect(
    *,
    seeds: Sequence[bytes],
    output: Path,
    services: Mapping[str, tuple],
    random_seed: int,
    workers: int,
    timeout: float,
) -> dict:
    suite = deterministic_payloads(seeds, random_seed=random_seed)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=output.parent)
    counts = {"tcp": {}, "udp": {}}
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for transport in ("tcp", "udp"):
                members = _transport_members(services, transport)
                tester = ServiceTester(
                    members, timeout=timeout,
                    banner_timeout=min(timeout, float(getattr(config, "BANNER_TIMEOUT", 0.05))),
                )
                baseline_kind = "connect_only" if transport == "tcp" else "zero_length"
                for idx in range(16):
                    if transport == "tcp":
                        responses = connect_only_parallel(
                            members, timeout=min(timeout, 0.2), workers=workers)
                    else:
                        responses = tester.test_packets_parallel(
                            [b""], max_workers=workers, batch_size=1)[0]
                    row = {
                        "transport": transport,
                        "probe_kind": baseline_kind,
                        "control_id": f"{transport}:{baseline_kind}:{idx:02d}",
                        "packet_hash": hashlib.sha256(b"").hexdigest(),
                        "packet_len": 0,
                        "responses": [response_record(r) for r in responses],
                    }
                    handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                counts[transport][baseline_kind] = 16

                for kind in ("random", "shuffled"):
                    for idx, payload in enumerate(suite[kind]):
                        responses = tester.test_packets_parallel(
                            [payload], max_workers=workers, batch_size=1)[0]
                        row = {
                            "transport": transport,
                            "probe_kind": kind,
                            "control_id": f"{transport}:{kind}:{idx:02d}",
                            "packet_hash": hashlib.sha256(payload).hexdigest(),
                            "packet_len": len(payload),
                            "responses": [response_record(r) for r in responses],
                        }
                        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                    counts[transport][kind] = len(suite[kind])
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, output)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return {
        "output": str(output),
        "random_seed": random_seed,
        "counts": counts,
        "total_records": sum(sum(v.values()) for v in counts.values()),
        "members": {
            t: len(_transport_members(services, t)) for t in ("tcp", "udp")
        },
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--random-seed", type=int, default=20260825)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=0.5)
    args = parser.parse_args()
    universe = None
    manifest = collect(
        seeds=load_seed_packets(args.seeds_file), output=args.output,
        services=config.SERVICES, random_seed=args.random_seed,
        workers=args.workers, timeout=args.timeout,
    )
    if universe is not None:
        manifest["e1_training_universe"] = {
            "artifact_hash": universe["artifact_hash"],
            "policy_file_sha256": universe["policy_file_sha256"],
            "service_topology_hash": universe["service_topology_hash"],
            "retained_member_count": universe["retained_member_count"],
            "excluded_members": universe["excluded_members"],
        }
    rendered = json.dumps(manifest, indent=2, ensure_ascii=False)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)

if __name__ == "__main__":
    main()
