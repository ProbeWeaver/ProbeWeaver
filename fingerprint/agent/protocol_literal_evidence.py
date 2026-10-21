"""Reviewed response literals bound to approved local source bytes and corpus.

This is a narrow supplement to the echo guard, not a general "found in docs"
bypass. Additions require review of the *server response* context. The source
allowlist/hash, exact literal, target and construction identity are rechecked
by the validator. Full-function precision/coverage gates remain unchanged.
"""
import hashlib
import json
from pathlib import Path

from protocol.source_catalog import ROOT, catalog, source_files

# Reviewed against docs/rethinkdb/rethinkdb.txt, Perform a handshake (V1_0
# and V0_3/V0_4), and docs/sip/sip.txt section 7.2. Version strings, arbitrary
# request fields and generic error messages are deliberately not admitted.
_REVIEWED = {
    'rethinkdb': {
        b'"min_protocol_version"': ('docs/rethinkdb/rethinkdb.txt', 'V1_0 server JSON handshake'),
        b'"max_protocol_version"': ('docs/rethinkdb/rethinkdb.txt', 'V1_0 server JSON handshake'),
        b'"server_version"': ('docs/rethinkdb/rethinkdb.txt', 'V1_0 server JSON handshake; value is not pinned'),
        b'SUCCESS': ('docs/rethinkdb/rethinkdb.txt', 'V0_3/V0_4 server NUL-terminated handshake result'),
    },
    'sip': {
        b'SIP/2.0': ('docs/sip/sip.txt', 'RFC 3261 sections 7.1/7.2; response Status-Line'),
        b'Via:': ('docs/sip/sip.txt', 'RFC 3261 section 8.2.6.2; response Via header, value is not pinned'),
    },
}

def analyze_protocol_literal(literal, *, target, corpus_identity):
    reviewed = _REVIEWED.get(target, {}).get(literal)
    if reviewed is None:
        return None
    relative, section = reviewed
    approved = {Path(p).resolve() for p in source_files(target)}
    path = (ROOT / relative).resolve()
    if path not in approved or path.suffix not in {'.txt', '.md'}:
        raise ValueError('Reviewed literal is not in an approved text source')
    raw = path.read_bytes()
    if literal not in raw:
        raise ValueError('Reviewed literal disappeared from approved source')
    source_sha = hashlib.sha256(raw).hexdigest()
    # source_files already checks this, but bind the precise entry explicitly.
    source = next(s for s in catalog()[target]['sources'] if s['path'] == relative)
    if source['sha256'] != source_sha:
        raise ValueError('Reviewed source hash changed')
    result = dict(kind='reviewed_protocol_response_literal', eligible=True,
                  value_hex=literal.hex(), target=target, corpus_identity=corpus_identity,
                  source_path=relative, source_sha256=source_sha, section=section,
                  source_byte_offset=raw.index(literal),
                  review_policy='response-side-source-review-v1; not standalone identification evidence')
    result['evidence_id'] = 'protocol-literal-v1:' + hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result

def bind_literal_justifications(justifications, verified_by_literal):
    """Do not let an ID for one literal authorize a different echoed literal."""
    prefixes = ('protocol-literal-v1:', 'response-literal-v1:')
    return [j for j in justifications if all(
        not str(e).startswith(prefixes)
        or e in verified_by_literal.get(j.get('constant_hex'), set())
        for e in j.get('evidence_ids', []))]
