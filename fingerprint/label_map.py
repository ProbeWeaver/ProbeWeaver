"""Canonical service labels and aliases. Unknown labels retain their identity rather than being guessed."""

from config import SERVICE_CLUSTERS

CLUSTER_ALIASES = {
    "bittorrent": "bittorrentv10",
    "imap": "imapv4",
    "smb2": "smb",
}

CANONICAL_CLUSTERS = list(SERVICE_CLUSTERS.keys())

def canonicalize(label: str) -> str:
    """Map known aliases to canonical service labels; preserve unknown labels."""
    return CLUSTER_ALIASES.get(label, label)
