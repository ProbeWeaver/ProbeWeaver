"""Corpus-bound, response-side evidence for explicitly proposed Go literals.

This supplements the brief analyzer's top-N findings; it does not replace the
echo guard or the full Go precision/coverage gates. An ID is valid only when
independently recomputed from the current corpus and target.
"""
import hashlib
import json

def analyze_literal(literal, observations, negatives, *, target, corpus_identity):
    pairs = []
    for row in observations:
        packet, response = row.get('packet'), row.get('response')
        if isinstance(packet, str):
            packet = bytes.fromhex(packet)
        if isinstance(response, str):
            response = bytes.fromhex(response)
        if isinstance(packet, bytes) and isinstance(response, bytes):
            pairs.append((packet, response))
    supporting = [(p, r) for p, r in pairs if literal in r]
    independent = [(p, r) for p, r in supporting if literal not in p]
    neg_rates = {k: sum(literal in r for r in rs)/len(rs)
                 for k, rs in sorted(negatives.items()) if rs}
    result = dict(kind='response_side_literal', value_hex=literal.hex(),
                  target=target, corpus_identity=corpus_identity,
                  supporting_atoms=len(supporting),
                  nonverbatim_atoms=len(independent),
                  nonverbatim_packets=len({p for p, _ in independent}),
                  negative_rates=neg_rates)
    # A candidate must repeatedly occur without being sent verbatim, and be
    # discriminating even before the enclosing Go predicate is evaluated.
    result['eligible'] = bool(len(literal) >= 4 and len(independent) >= 20
        and len({p for p, _ in independent}) >= 2
        and len(independent) >= .95 * len(supporting)
        and neg_rates and max(neg_rates.values()) <= .02)
    digest = hashlib.sha256(json.dumps(result, sort_keys=True,
                            separators=(',', ':')).encode()).hexdigest()
    result['evidence_id'] = 'response-literal-v1:' + digest
    return result
