"""Service-level response facts and nested serialization. Observed services are the banner/post-send union. Passive services have banners but no post-send bytes. Payload-triggered services have post-send bytes; this timing observation does not prove semantic causation."""

import hashlib
from typing import Dict, List, Optional, Set, Iterator, Tuple

from config import cluster_of
from core.service_tester import ServiceResponse

def triggered_clusters_from(responses: List[ServiceResponse]) -> Set[str]:
    """Return the legacy observed union of banner and post-send services."""
    return {
        cluster_of(r.service_name)
        for r in responses
        if r.response_bytes
    }

def observed_clusters_from(responses: List[ServiceResponse]) -> Set[str]:
    """Return services observed in either response phase."""
    return {
        cluster_of(r.service_name)
        for r in responses
        if r.response_bytes or getattr(r, "banner_bytes", b"")
    }

def payload_triggered_clusters_from(responses: List[ServiceResponse]) -> Set[str]:
    """Return services with bytes observed after sending the payload."""
    return {
        cluster_of(r.service_name)
        for r in responses
        if getattr(r, "response_phase", "post_payload") == "post_payload"
        and bool(r.response_bytes)
    }

def passive_clusters_from(responses: List[ServiceResponse]) -> Set[str]:
    """Return banner-visible services with no post-send response in any variant."""
    bannered_clusters = {
        cluster_of(r.service_name)
        for r in responses
        if (
            bool(getattr(r, "banner_bytes", b""))
            or (
                getattr(r, "response_phase", "post_payload") == "pre_payload_banner"
                and bool(r.response_bytes)
            )
        )
    }
    return bannered_clusters - payload_triggered_clusters_from(responses)

def group_responses_by_cluster(
    responses: List[ServiceResponse],
) -> Dict[str, List[ServiceResponse]]:
    """Group nonempty implementation responses by service in encounter order."""
    grouped: Dict[str, List[ServiceResponse]] = {}
    for r in responses:
        if not r.response_bytes:
            continue
        grouped.setdefault(cluster_of(r.service_name), []).append(r)
    return grouped

def cluster_pattern_key(responses: List[ServiceResponse]) -> frozenset:
    """Return a frozen set of service/response-byte pairs."""
    return frozenset(
        (cluster_of(r.service_name), r.response_bytes)
        for r in responses
        if r.response_bytes
    )

def cluster_pattern_key_from_tuples(responses_tuples: List[tuple]) -> frozenset:
    """Build a service-level pattern from worker response tuples."""
    return frozenset(
        (cluster_of(member), resp)
        for member, resp, _lat in responses_tuples
        if resp
    )

def cluster_pattern_digest_from_tuples(responses_tuples: List[tuple]) -> str:
    """Hash the exact service-level response pattern."""
    pairs = {
        (cluster_of(member), bytes(resp))
        for member, resp, _lat in responses_tuples
        if resp
    }
    h = hashlib.blake2b(digest_size=20, person=b"pf-cluster-v1")
    for cluster, response in sorted(pairs, key=lambda item: (item[0], item[1])):
        cluster_bytes = cluster.encode("utf-8", errors="surrogatepass")
        h.update(len(cluster_bytes).to_bytes(4, "big"))
        h.update(cluster_bytes)
        h.update(len(response).to_bytes(8, "big"))
        h.update(response)
    return h.hexdigest()

def target_pattern_digest_from_responses(
    responses: List[ServiceResponse], target_cluster: str
) -> str:
    """Hash the target response pattern for bounded reachability retention."""
    tuples = [
        (r.service_name, r.response_bytes, r.latency_ms)
        for r in responses
        if r.response_bytes and cluster_of(r.service_name) == target_cluster
    ]
    return cluster_pattern_digest_from_tuples(tuples)

def candidate_to_nested_dict(
    packet: bytes,
    responses: List[ServiceResponse],
    mutation_target: Optional[str],
    iteration: int,
    transport: str = "",
    candidate_type: str = "multi_probe",
    origin_protocol: Optional[str] = None,
    objective_version: Optional[str] = None,
    weight_config_hash: Optional[str] = None,
) -> Dict:
    """Serialize a candidate into the nested service/implementation schema."""
    grouped = group_responses_by_cluster(responses)
    nested_groups = []
    for cluster in sorted(grouped.keys()):
        members = sorted(grouped[cluster], key=lambda r: r.service_name)
        member_records = []
        for r in members:
            item = {
                "service": r.service_name,
                "response_hex": r.response_bytes.hex(),
                "latency_ms": r.latency_ms,
            }
            if objective_version == "background_adjusted_breadth":
                item.update({
                    "banner_hex": getattr(r, "banner_bytes", b"").hex(),
                    "response_phase": getattr(
                        r, "response_phase", "legacy_unknown"),
                    "banner_latency_ms": getattr(
                        r, "banner_latency_ms", 0.0),
                    "payload_latency_ms": getattr(
                        r, "payload_latency_ms", 0.0),
                })
            member_records.append(item)
        nested_groups.append({
            "service": cluster,
            "responses": member_records,
        })
    record = {
        "packet_hex": packet.hex(),
        "iteration": iteration,
        "transport": transport,
        "responses": nested_groups,
        "candidate_type": candidate_type,
    }
    if mutation_target is not None:
        record["mutation_target"] = mutation_target
    if origin_protocol is not None:
        record["origin_protocol"] = origin_protocol
    if objective_version:
        record["objective_version"] = objective_version
    if weight_config_hash:
        record["weight_config_hash"] = weight_config_hash
    if objective_version == "background_adjusted_breadth":
        record.update({
            "observed_clusters": sorted(observed_clusters_from(responses)),
            "passive_clusters": sorted(passive_clusters_from(responses)),
            "payload_triggered_clusters": sorted(
                payload_triggered_clusters_from(responses)),
        })
    return record

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

def iter_nested_responses(record: Dict) -> Iterator[Tuple[str, str, str, float]]:
    """Yield service, implementation, response hex and latency from nested records."""
    for group in record.get('responses', []):
        cluster = group.get('service')
        for m in group.get('responses', []):
            yield cluster, m.get('service'), m.get('response_hex', ''), m.get('latency_ms', 0.0)

def nested_record_pattern_key(record: Dict) -> frozenset:
    """Return the exact service/response pattern of a nested record."""
    return frozenset(
        (cluster, rh)
        for cluster, _member, rh, _lat in iter_nested_responses(record)
        if rh
    )

def nested_record_clusters(record: Dict) -> Set[str]:
    """Return the outer service labels of a nested response record."""
    return {group.get('service') for group in record.get('responses', [])}

def record_mutation_target(record: Dict) -> str:
    """Read mutation_target with a legacy origin fallback for old records."""
    mt = record.get('mutation_target')
    if mt:
        return mt
    return record.get('origin_protocol', '') or ''

def record_candidate_type(record: Dict) -> str:
    """Read the candidate channel; legacy records default to multi_probe."""
    return record.get('candidate_type') or 'multi_probe'
