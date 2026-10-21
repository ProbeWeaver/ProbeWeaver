"""Local Spec Agent tools: inventory, rag, read-source, validate, submit.

Always run through `mamba run -n protocol_fuzzer python scripts/spec_agent.py`.
No tool sends network probes. Submit is opt-in and requires evidence + review.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from protocol.source_catalog import ROOT, CATALOG, catalog, canonical_name, source_files
from protocol.spec_agent import sha, validation_receipt, verify_receipt, load_candidate

def document_lines(path):
    path = Path(path)
    if path.suffix.lower() == ".pdf":
        text = subprocess.check_output(["pdftotext", "-layout", str(path), "-"], text=True)
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
    return text.splitlines()

def retrieve(name, query, top_k=5, backend="lexical"):
    files = source_files(name)
    chunks = []
    if backend == "vector":
        from rag.retriever import create_retriever
        retriever = create_retriever()
        index = retriever.build_index(name)
        nodes = index.as_retriever(similarity_top_k=top_k).retrieve(query)
        for node in nodes:
            path = node.node.metadata.get("file_path")
            if not path:
                raise ValueError("vector result lacks file_path provenance; use lexical retrieval")
            path = str(Path(path).resolve())
            if path not in files:
                raise ValueError("vector result outside approved source set")
            chunks.append({"source": str(Path(path).relative_to(ROOT)), "source_sha256": sha(path),
                           "node_id": node.node.node_id, "score": node.score,
                           "text": node.node.get_content(), "metadata": node.node.metadata})
    else:
        # Deterministic local retrieval, no API key/model needed. Scores are
        # lexical retrieval scores, never normative confidence or proof.
        terms = set(re.findall(r"[a-z0-9_]+", query.lower()))
        for path in files:
            lines = document_lines(path)
            for start in range(0, len(lines), 24):
                snippet = "\n".join(lines[start:start + 48])
                words = re.findall(r"[a-z0-9_]+", snippet.lower())
                score = sum(math.log1p(words.count(term)) for term in terms)
                if score:
                    chunks.append({"source": str(Path(path).relative_to(ROOT)), "source_sha256": sha(path),
                                   "start_line": start + 1, "end_line": min(start + 48, len(lines)),
                                   "score": score, "text": snippet})
        chunks.sort(key=lambda c: (-c["score"], c["source"], c["start_line"]))
        chunks = chunks[:top_k]
    if not chunks:
        raise ValueError("no evidence retrieved; refine query/read source, do not invent fields")
    return {"schema_version": 1, "protocol": name, "query": query, "backend": backend,
            "catalog_sha256": sha(CATALOG), "hits": chunks}

def verify_evidence(name, evidence):
    if evidence.get("protocol") != name or evidence.get("catalog_sha256") != sha(CATALOG) or not evidence.get("hits"):
        raise ValueError("missing/stale protocol-bound RAG evidence")
    allowed = set(source_files(name))
    for hit in evidence["hits"]:
        path = (ROOT / hit["source"]).resolve()
        if str(path) not in allowed or hit["source_sha256"] != sha(path):
            raise ValueError("evidence source mismatch")
        lines = document_lines(path)
        if "start_line" in hit:
            a, b = hit["start_line"], hit["end_line"]
            if not 1 <= a <= b <= len(lines) or "\n".join(lines[a - 1:b]) != hit["text"]:
                raise ValueError("evidence span/text mismatch")
        elif " ".join(hit["text"].split()) not in " ".join("\n".join(lines).split()):
            raise ValueError("vector text not found in current source; use exact source spans")

def submit(name, candidate, receipt, evidence, review, *, apply=False):
    verify_receipt(name, candidate, receipt)
    verify_evidence(name, evidence)
    target = ROOT / catalog()[name]["spec_file"]
    expected = {"protocol": name, "candidate_sha256": sha(candidate), "target_sha256": sha(target)}
    if any(review.get(k) != v for k, v in expected.items()) or review.get("decision") != "approve" or not review.get("reviewer"):
        raise ValueError("missing approval bound to candidate AND current target")
    if not review.get("field_evidence") or not review.get("limitations") or not review.get("cross_field_dependencies"):
        raise ValueError("review must record field evidence, dependencies and limitations")
    spec = load_candidate(Path(candidate).read_text(encoding="utf-8"), name)
    required = {f.name for f in spec.fields if f.length}
    mapping = review["field_evidence"]
    if not isinstance(mapping, dict) or set(mapping) != required:
        raise ValueError("review field_evidence must map EVERY non-marker field")
    for field, refs in mapping.items():
        if not isinstance(refs, list) or not refs or any(type(i) is not int or not 0 <= i < len(evidence["hits"]) for i in refs):
            raise ValueError(f"invalid evidence hit references for {field}")
    if not apply:
        return {"status": "ready_for_explicit_apply", "target": str(target)}
    # Read old bytes only after all gates passed; preserve a content-addressed backup.
    old = target.read_bytes()
    backup = ROOT / ".cache/spec-gen/backups" / (target.name + "." + hashlib.sha256(old).hexdigest())
    backup.parent.mkdir(parents=True, exist_ok=True)
    if not backup.exists():
        backup.write_bytes(old)
    new = Path(candidate).read_bytes()
    if hashlib.sha256(new).hexdigest() != receipt["candidate_sha256"] or sha(target) != review["target_sha256"]:
        raise ValueError("candidate/target changed before write")
    fd, temp = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(new)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return {"status": "applied", "target": str(target), "backup": str(backup), "git_committed": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "rag", "read-source", "validate", "submit"))
    parser.add_argument("--protocol")
    parser.add_argument("--candidate")
    parser.add_argument("--query")
    parser.add_argument("--backend", choices=("lexical", "vector"), default="lexical")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--source-index", type=int, default=0)
    parser.add_argument("--start-line", type=int, default=1)
    parser.add_argument("--lines", type=int, default=100)
    parser.add_argument("--receipt")
    parser.add_argument("--evidence")
    parser.add_argument("--review")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        name = canonical_name(args.protocol) if args.protocol else None
        entries = catalog()
        if args.command in ("rag", "read-source", "submit") and name is None:
            raise ValueError("--protocol is required")
        if name is not None and name not in entries:
            raise ValueError("unknown/ambiguous identity; register exact protocol first")
        if not 1 <= args.top_k <= 30:
            raise ValueError("top-k must be 1..30")
        if args.command == "inventory":
            result = entries[name] if name else entries
        elif args.command == "rag":
            if not args.query:
                raise ValueError("--query required")
            result = retrieve(name, args.query, args.top_k, args.backend)
        elif args.command == "read-source":
            files = source_files(name)
            if not 0 <= args.source_index < len(files) or args.start_line < 1 or not 1 <= args.lines <= 500:
                raise ValueError("source index/range out of bounds")
            path = files[args.source_index]
            lines = document_lines(path)
            start = args.start_line - 1
            result = {"source": str(Path(path).relative_to(ROOT)), "sha256": sha(path),
                      "start_line": start + 1, "end_line": min(start + args.lines, len(lines)),
                      "text": "\n".join(lines[start:start + args.lines])}
        elif args.command == "validate":
            if args.candidate and not name:
                raise ValueError("candidate validation requires --protocol")
            selected = [name] if name else sorted(entries)
            results = [validation_receipt(n, args.candidate or ROOT / entries[n]["spec_file"]) for n in selected]
            result = results[0] if name else {"protocol_count": len(results), "profile_count": sum(len(r["results"]) for r in results), "receipts": results}
        else:
            if not all((args.candidate, args.receipt, args.evidence, args.review)):
                raise ValueError("submit requires candidate, receipt, evidence and review")
            read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
            result = submit(name, args.candidate, read(args.receipt), read(args.evidence), read(args.review), apply=args.apply)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.out:
            out = Path(args.out)
            # Artifacts must never overwrite source files or approved documents.
            if out.suffix != ".json" or out.resolve() in {CATALOG.resolve(), *(Path(p).resolve() for e in entries.values() for p in [ROOT / e["spec_file"]])}:
                raise ValueError("--out must be a separate JSON artifact")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + "\n", encoding="utf-8")
            print(json.dumps({"artifact": str(out.resolve()), "command": args.command, "status": "ok"}))
        else:
            print(text)
    except (ValueError, OSError, TypeError, KeyError, IndexError, SyntaxError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
