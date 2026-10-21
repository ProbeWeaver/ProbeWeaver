"""Explicit protocol identity, source allowlists and content hashes."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = Path(__file__).with_name("spec_sources.json")
ALIASES = {"imap": "imapv4", "ntp": "ntpv4", "socks": "socks5",
           "portmap": "portmapv2", "bittorrent": "bittorrentv10",
           "mqtt-v3.1.1": "mqttv311", "mqtt-v5.0": "mqttv50"}

def catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))["profiles"]

def canonical_name(name):
    name = name.lower()
    return ALIASES.get(name, name)

def source_files(name, docs_dir=None, *, verify=True):
    name = canonical_name(name)
    entry = catalog().get(name)
    if entry is None:
        raise ValueError(f"No approved source identity for {name}; disambiguate/register first")
    base = Path(docs_dir) if docs_dir else ROOT / "docs"
    result = []
    for source in entry["sources"]:
        path = base / Path(source["path"]).relative_to("docs")
        if not path.is_file():
            raise FileNotFoundError(f"Missing approved source: {path}; no legacy fallback")
        if verify and hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
            raise ValueError(f"Source changed: {path}; review and refresh manifest before admission")
        result.append(str(path.resolve()))
    return result
