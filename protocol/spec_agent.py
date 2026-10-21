"""Spec Agent admission primitives. Candidate Python is interpreted, never exec'd."""
import ast
import hashlib
import json
from pathlib import Path
from protocol.field import FieldDefinition, FieldType, SurvivalType, UnifiedProtocolSpec
from protocol.profile import F, I, B, E, L
from protocol.source_catalog import ROOT, CATALOG, catalog, source_files
from protocol.validation import validate_spec

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load_candidate(code, expected_name=None):
    """Small declarative AST language. Reject imports/calls/comprehensions with effects."""
    if len(code) > 250000:
        raise ValueError("candidate too large")
    tree = ast.parse(code)
    if sum(1 for _ in ast.walk(tree)) > 12000:
        raise ValueError("candidate AST too large")
    constructors = {"FieldDefinition": FieldDefinition, "F": F, "I": I, "B": B, "E": E, "L": L}
    attrs = {}

    def value(node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes)) and len(node.value) > 65536:
                raise ValueError("literal too large")
            if type(node.value) is int and node.value.bit_length() > 64:
                raise ValueError("integer literal exceeds fixed profile schema bound")
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            seq = [value(n) for n in node.elts]
            return seq if isinstance(node, ast.List) else tuple(seq)
        if isinstance(node, ast.Name) and node.id in attrs:
            return attrs[node.id]
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            enum = {"FieldType": FieldType, "SurvivalType": SurvivalType}.get(node.value.id)
            if enum and node.attr in enum.__members__:
                return enum[node.attr]
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left, right = value(node.left), value(node.right)
            if isinstance(node.op, ast.Add) and isinstance(left, bytes) and isinstance(right, bytes) and len(left) + len(right) <= 65536:
                return left + right
            if isinstance(node.op, ast.Mult) and isinstance(left, bytes) and type(right) is int and 0 <= right <= 65536 and len(left) * right <= 65536:
                return left * right
            raise ValueError("only bounded bytes concatenation/repetition allowed")
        if isinstance(node, ast.Call):
            args = [value(n) for n in node.args]
            if any(k.arg is None for k in node.keywords):
                raise ValueError("no keyword unpacking")
            kwargs = {k.arg: value(k.value) for k in node.keywords}
            if isinstance(node.func, ast.Name) and node.func.id in constructors:
                if node.func.id in ("I", "L") and (len(args) < 2 or type(args[1]) is not int or not 1 <= args[1] <= 65536):
                    raise ValueError("bounded positive field width required")
                if node.func.id == "FieldDefinition":
                    width = kwargs.get("length", args[1] if len(args) > 1 else None)
                    if type(width) is not int or not 0 <= width <= 65536:
                        raise ValueError("bounded field length required")
                return constructors[node.func.id](*args, **kwargs)
            if isinstance(node.func, ast.Name) and node.func.id == "bytes" and not kwargs and len(args) == 1 and type(args[0]) is int and 0 <= args[0] <= 65536:
                return bytes(args[0])
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "bytes" and node.func.attr == "fromhex" and len(args) == 1 and isinstance(args[0], str) and not kwargs:
                return bytes.fromhex(args[0])
        raise ValueError(f"unsupported candidate expression: {type(node).__name__}")

    classes = []
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom) and node.module in ("protocol.field", "protocol.profile") and node.level == 0:
            allowed = set(constructors) | {"FieldType", "SurvivalType", "UnifiedProtocolSpec"}
            if all(n.name in allowed and n.asname is None for n in node.names):
                continue
        if isinstance(node, ast.ClassDef):
            classes.append(node)
            continue
        raise ValueError("module must contain only approved imports and one declarative class")
    if len(classes) != 1:
        raise ValueError("exactly one spec class required")
    cls = classes[0]
    if cls.decorator_list or cls.keywords or len(cls.bases) != 1 or not isinstance(cls.bases[0], ast.Name) or cls.bases[0].id != "UnifiedProtocolSpec":
        raise ValueError("class must directly inherit UnifiedProtocolSpec, without decorators")
    allowed_attrs = {"name", "default_port", "transport", "profile_version", "source_refs", "profile_scope", "description", "fields"}
    for node in cls.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name) or node.targets[0].id not in allowed_attrs:
            raise ValueError("class body must contain only metadata and field declarations")
        key = node.targets[0].id
        if key in attrs:
            raise ValueError("duplicate class attribute")
        attrs[key] = value(node.value)
    if expected_name is not None and attrs.get("name") != expected_name:
        raise ValueError("candidate protocol identity mismatch")
    if not isinstance(attrs.get("fields"), list) or not all(isinstance(f, FieldDefinition) for f in attrs["fields"]):
        raise ValueError("fields must be FieldDefinition objects")
    if not attrs.get("source_refs") or not attrs.get("profile_scope") or attrs.get("profile_version", "legacy") == "legacy":
        raise ValueError("source_refs, profile_scope and profile_version required")
    if not isinstance(attrs["source_refs"], (list, tuple)) or not all(isinstance(r, str) and r.strip() for r in attrs["source_refs"]):
        raise ValueError("source_refs must be explicit document/section strings")
    if attrs.get("transport") not in ("tcp", "udp", "both") or type(attrs.get("default_port")) is not int or not 1 <= attrs["default_port"] <= 65535:
        raise ValueError("explicit transport and valid default_port required")
    if sum(f.length for f in attrs["fields"]) > 65536:
        raise ValueError("profile too large")
    return type(cls.name, (UnifiedProtocolSpec,), attrs)()

def engine_snapshot():
    paths = ["protocol/field.py", "protocol/profile.py", "protocol/length_codec.py",
             "protocol/validation.py", "protocol/spec_agent.py", "protocol/source_catalog.py",
             "scripts/spec_agent.py", "core/mutator.py", "core/priority_mapper.py", "core/reinforcement_learning.py"]
    return {p: sha(ROOT / p) for p in paths}

def validation_receipt(name, candidate):
    source_files(name)  # Hash-check approved original documents, not cached snippets.
    entry = catalog()[name]
    path = Path(candidate)
    spec = load_candidate(path.read_text(encoding="utf-8"), name)
    if type(spec).__name__ != entry["class_name"]:
        raise ValueError("existing public class name must be preserved")
    if spec.transport != entry["transport"] or spec.default_port != entry["default_port"]:
        raise ValueError("transport/port differs from approved identity; review catalog first")
    if entry["identity"] not in spec.source_refs:
        raise ValueError("source_refs must include the approved protocol identity")
    transports = ("tcp", "udp") if spec.transport == "both" else (spec.transport,)
    results = [validate_spec(spec.for_transport(t)) for t in transports]
    return {"schema_version": 1, "protocol": name, "candidate_sha256": sha(path),
            "catalog_sha256": sha(CATALOG), "engine": engine_snapshot(),
            "source_snapshot": entry["sources"], "results": results,
            "status": "offline_pass", "network_tested": False,
            "limitations": ["bounded profile only", "single-field positive alternatives, not all combinations", "no deployment/recognition coverage assertion"]}

def verify_receipt(name, candidate, receipt):
    actual = validation_receipt(name, candidate)
    if actual != receipt:
        raise ValueError("validation receipt stale or changed; rerun validation")
    return actual
