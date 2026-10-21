"""Shared service weights for search and selection. Combine log-scaled Censys counts and manually assigned importance; missing counts use the median over normalized service categories. Divide each service weight among its variants."""

from __future__ import annotations

import hashlib
import json
import logging
import math
from statistics import median
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

logger = logging.getLogger(__name__)

# ============================================================================

# ============================================================================

CENSYS_COUNTS: Dict[str, int] = {
    "http":        54141638,
    "http2":       52521615,
    "ssh":         22195950,
    "cwmp":        21846376,
    "snmp":        13995481,
    "ike":         10110161,
    "ftp":          6030675,
    "sip":          6335632,
    "ntp":          5698971,
    "dns":          3716549,
    "l2tp":         3308763,
    "pop3":         2739799,
    "imap":         2734016,
    "rdp":          2551489,
    "rtsp":         2539590,
    "telnet":        925446,
    "smb2":          830879,
    "mqttv311":      737298,
    "mqttv50":       737298,
    "portmap":      1435934,
    "redis":          343521,
    "mongodb":        305589,
    "irc":            294230,
    "bittorrent":     294945,
    "socks":          428407,
    "x11":            423439,
    "ldap":            66674,
    "modbus":          69013,
    "amqp":           142635,
    "memcached":       21418,
    "bolt":             6726,
    "rethinkdb":        4437,
}

SECURITY_WEIGHTS: Dict[str, float] = {
    "http": 1.0, "http2": 1.0, "ssh": 1.0, "dns": 1.0, "tls": 1.0,
    "ftp": 0.6, "smtp": 0.6, "imap": 0.6, "pop3": 0.6,
    "mqttv311": 0.8, "mqttv50": 0.8, "modbus": 0.8, "rdp": 0.8, "smb2": 0.8, "ldap": 0.8,
    "redis": 0.6, "mongodb": 0.6, "memcached": 0.6, "rtsp": 0.6, "ntp": 0.6,
    "amqp": 0.6, "bittorrent": 0.3, "cwmp": 0.3, "snmp": 0.6, "ike": 0.3,
    "sip": 0.3, "bolt": 0.3, "rethinkdb": 0.3, "lpd": 0.3, "x11": 0.3,
    "irc": 0.3, "telnet": 0.6, "portmap": 0.3, "socks": 0.6, "l2tp": 0.3,
}

DEFAULT_SECURITY = 0.3     

CENSYS_KEY_OF_CLUSTER: Dict[str, str] = {
    "ikev2": "ike",
    "ntpv4": "ntp",
    "smb": "smb2",
    "portmapv2": "portmap",
    "bittorrentv10": "bittorrent",
    "socks5": "socks",
    "imapv4": "imap",
}

def censys_key_of_cluster(cluster: str) -> str:
    """Map a service to its normalized prevalence-count category."""
    return CENSYS_KEY_OF_CLUSTER.get(cluster, cluster)

MISSING_COUNT_POLICY = "median_available_service_categories_v1"

def median_service_count(counts: Dict[str, int]) -> float:
    """Missing-count estimate from the fixed reference table, one count per category.

    Aliases and the two MQTT versions must not duplicate a category. Prefer
    the canonical entry if an alias is also present. No synthetic estimates
    are added to the reference table itself.
    """
    categories = {}
    for key, value in sorted(counts.items()):
        if value < 0:
            raise ValueError(f"Censys count for {key!r} must be >= 0, got {value}")
        category = censys_key_of_cluster(key)
        if category == "mqttv50":
            category = "mqttv311"
        if category not in categories or key == category:
            categories[category] = value
    if not categories:
        raise ValueError("Median count imputation requires at least one available Censys count")
    return float(median(categories.values()))

# Compatibility export: derived from observed counts, no fixed arbitrary value.
DEFAULT_COUNT = median_service_count(CENSYS_COUNTS)

def parse_summary_txt(path: str) -> Dict[str, int]:
    """Parse service, retrieved-count and total-count columns."""
    out: Dict[str, int] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue  
            name, total_raw = parts[0], parts[2]
            try:
                out[name] = int(total_raw.replace(",", ""))
            except ValueError:
                continue  
    return out

def load_censys_counts(summary_path: str = None) -> Dict[str, int]:
    """Load frozen counts with optional local overrides."""
    counts = dict(CENSYS_COUNTS)
    if summary_path and Path(summary_path).is_file():
        try:
            live = parse_summary_txt(summary_path)
            counts.update(live)
            logger.debug("Refreshed counts from %s: %d Censys entries", summary_path, len(live))
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to parse %s; using frozen counts: %s", summary_path, e)
    return counts

# ============================================================================

# ============================================================================

def compute_cluster_weights(
    clusters: Set[str],
    prevalence_alpha: float = 0.7,
    counts: Optional[Dict[str, int]] = None,
    security_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """Normalize the mixture of log prevalence and assigned importance."""
    if not 0.0 <= prevalence_alpha <= 1.0:
        raise ValueError(
            f"prevalence_alpha must be in [0,1], got {prevalence_alpha}"
        )
    if counts is None:
        counts = CENSYS_COUNTS
    if security_weights is None:
        security_weights = SECURITY_WEIGHTS
    if not clusters:
        return {}
    missing_count = median_service_count(counts)
    raw: Dict[str, float] = {}
    for c in clusters:
        key = censys_key_of_cluster(c)
        count = counts.get(key, missing_count)
        if count < 0:
            raise ValueError(f"Censys count for {key!r} must be >= 0, got {count}")
        prev = math.log10(count + 1)
        sec = security_weights.get(key, DEFAULT_SECURITY)
        if sec < 0:
            raise ValueError(f"security weight for {key!r} must be >= 0, got {sec}")
        raw[c] = prevalence_alpha * prev + (1.0 - prevalence_alpha) * sec
    total = sum(raw.values())
    if total <= 0:
        n = max(1, len(clusters))
        return {c: 1.0 / n for c in clusters}
    return {c: v / total for c, v in raw.items()}

def normalize_excluding_target(
    weights: Dict[str, float],
    target: str,
) -> Dict[str, float]:
    """Remove the target and renormalize weights for additional-service breadth."""
    rest = {c: float(w) for c, w in weights.items() if c != target}
    total = sum(rest.values())
    if total <= 0:
        return {c: 0.0 for c in rest}
    return {c: w / total for c, w in rest.items()}

# ============================================================================

# ============================================================================

def weight_config_hash(
    prevalence_alpha: float = 0.7,
    counts: Optional[Dict[str, int]] = None,
    security_weights: Optional[Dict[str, float]] = None,
) -> str:
    """Hash the complete weight configuration."""
    if counts is None:
        counts = CENSYS_COUNTS
    if security_weights is None:
        security_weights = SECURITY_WEIGHTS
    payload = {
        "missing_count_policy": MISSING_COUNT_POLICY,
        "alpha": float(prevalence_alpha),
        "counts": {k: int(v) for k, v in sorted(counts.items())},
        "security": {k: float(v) for k, v in sorted(security_weights.items())},
    }
    blob = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

def weight_config_metadata(
    clusters: Iterable[str] = (),
    prevalence_alpha: float = 0.7,
    counts: Optional[Dict[str, int]] = None,
    security_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, object]:
    """Return the weight hash, settings and optional universe size."""
    cluster_set = set(clusters) if clusters is not None else set()
    effective_counts = CENSYS_COUNTS if counts is None else counts
    return {
        "weight_config_hash": weight_config_hash(
            prevalence_alpha, counts, security_weights),
        "prevalence_alpha": float(prevalence_alpha),
        "n_clusters": len(cluster_set),
        "missing_count_policy": MISSING_COUNT_POLICY,
        "missing_count_median": median_service_count(effective_counts),
        "imputed_clusters": sorted(
            c for c in cluster_set if censys_key_of_cluster(c) not in effective_counts),
    }
