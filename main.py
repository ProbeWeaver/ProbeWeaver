"""ProbeWeaver entry point. Load bounded profiles and seeds, split campaigns by transport, test the complete same-transport fleet and export phase-aware nested candidate records."""

import os

os.environ.setdefault("MALLOC_ARENA_MAX", "8")

import argparse
import glob
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import config
from core.clustering import candidate_to_nested_dict
from core.candidate_stream import export_candidate_streams
from core.service_weights import weight_config_hash
from core.orchestrator import (
    FuzzingOrchestrator,
    FingerprintCandidate,
    SeedRecord,
    load_seeds_from_file,
    save_seeds_to_file,
    deduplicate_candidates,
    _malloc_trim,
)
from protocol.field import UnifiedProtocolSpec

logger = logging.getLogger(__name__)

def _configure_logging(verbose: bool = False) -> None:
    """Configure CLI-owned handlers without side effects during module import.

    Experiment runners override ``config.LOG_*`` before calling :func:`main`, so
    handlers must be created at runtime rather than when this module is imported.
    Only handlers installed by this function are replaced; externally installed
    embedding applications keep ownership of their handlers.
    """
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, "_protocol_fuzzer_handler", False):
            root_logger.removeHandler(handler)
            handler.close()

    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    os.makedirs(config.LOG_DIR, exist_ok=True)
    file_handler = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_handler.setFormatter(formatter)
    file_handler._protocol_fuzzer_handler = True
    root_logger.addHandler(file_handler)

    if not config.LOG_TO_FILE_ONLY:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(formatter)
        console_handler._protocol_fuzzer_handler = True
        root_logger.addHandler(console_handler)

def load_services_from_config() -> Dict[str, tuple]:
    """Load target endpoints with transport metadata."""
    services = {}
    for name, info in config.SERVICES.items():
        transport = info.get('protocol', 'tcp')
        services[name] = (info['host'], info['port'], transport)
    return services

def load_services_from_file(filepath: str) -> Dict[str, tuple]:
    """Load endpoint configuration from JSON."""
    with open(filepath, 'r') as f:
        file_config = json.load(f)

    services = {}
    for name, info in file_config.items():
        if isinstance(info, dict):
            services[name] = (info['host'], info['port'])
        else:
            host, port = info.split(':')
            services[name] = (host, int(port))
    return services

def load_specs_from_directory(
    specs_dir: str,
    service_names: List[str] = None
) -> Dict[str, UnifiedProtocolSpec]:
    """Load protocol profile classes from a directory."""
    
    if service_names is None or len(service_names) == 0:
        service_names = None  

    specs = {}

    pattern = os.path.join(specs_dir, "*.py")
    spec_files = glob.glob(pattern)
    spec_files = [f for f in spec_files if not f.endswith('__init__.py')]

    logger.info(f"Found {len(spec_files)} spec files in {specs_dir}")

    if service_names:
        logger.info(f"Filtering by SERVICES_TO_FUZZ: {service_names}")
        service_names_lower = [s.lower() for s in service_names]

    for spec_file in spec_files:
        
        basename = os.path.basename(spec_file)
        service_name = basename[:-len(".py")]

        if service_names and service_name.lower() not in service_names_lower:
            logger.debug(f"Skipping {service_name} (not in services list)")
            continue

        try:
            spec = load_spec_from_file(spec_file)
            specs[spec.name] = spec
            logger.debug(f"Loaded spec: {spec.name} from {basename}")
        except Exception as e:
            logger.warning(f"Failed to load {spec_file}: {e}")

    logger.info(f"Loaded {len(specs)} protocol specs")
    logger.debug(f"Protocol specs: {list(specs.keys())}")
    return specs

def load_spec_from_file(filepath: str) -> UnifiedProtocolSpec:
    """Load one protocol profile module."""
    module_name = os.path.basename(filepath)[:-3]  

    spec = importlib.util.spec_from_file_location(module_name, filepath)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load spec from {filepath}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if isinstance(attr, type) and \
           issubclass(attr, UnifiedProtocolSpec) and \
           attr != UnifiedProtocolSpec:
            return attr()

    raise ValueError(f"No UnifiedProtocolSpec found in {filepath}")

def list_available_specs() -> List[str]:
    """List available profile classes."""
    specs_dir = config.PROTOCOL_SPECS_DIR
    spec_files = glob.glob(os.path.join(specs_dir, "*.py"))
    return sorted(
        Path(spec_file).stem
        for spec_file in spec_files
        if Path(spec_file).name != "__init__.py"
    )

def load_seeds(seeds_file: str = None) -> List[SeedRecord]:
    """Read input seed packets."""
    
    input_file = seeds_file if seeds_file else config.SEEDS_INPUT_FILE

    if not input_file:
        logger.error("No seed file specified! Set SEEDS_INPUT_FILE in config.py or use --seeds-input")
        return []

    records = load_seeds_from_file(input_file)
    if not records:
        logger.error(f"No seeds loaded from {input_file}")
        return []

    return records

def _scaled_thresholds(group_size: int) -> Tuple[int, int]:
    """Scale legacy fixed-count gates; current qualification does not use these thresholds."""
    scale_factor = getattr(config, 'THRESHOLD_SCALE_FACTOR', 1.0)
    raw_fp = getattr(config, 'FINGERPRINT_COLLECTION_THRESHOLD', 2)
    raw_seed = getattr(config, 'SEED_SELECTION_THRESHOLD', 2)
    if scale_factor < 1.0:
        scaled = max(2, int(group_size * scale_factor))
        return min(raw_fp, scaled), min(raw_seed, scaled)
    return raw_fp, raw_seed

def _get_transport(name: str, services: Dict, specs: Dict) -> str:
    """Resolve transport from endpoint configuration, then the profile."""
    svc = services.get(name)
    if svc and len(svc) >= 3:
        return svc[2]
    spec = specs.get(name)
    return spec.transport if spec else "tcp"

def _resolve_probe_targets(tokens):
    """Expand service or implementation selectors into endpoint keys."""
    if not tokens:
        return None
    resolved, unknown = set(), []
    for tok in tokens:
        if tok in config.SERVICE_CLUSTERS:
            resolved.update(config.SERVICE_CLUSTERS[tok])   
        elif tok in config.SERVICES:
            resolved.add(tok)                                
        else:
            unknown.append(tok)
    if unknown:
        logger.warning(f"_resolve_probe_targets: unknown tokens ignored (not cluster/member): {unknown}")
    return resolved

def run_fuzzing(
    specs: Dict[str, UnifiedProtocolSpec],
    services: Dict[str, tuple],
    initial_seeds: List[SeedRecord],
    target_protocols: List[str] = None,
    probe_targets: List[str] = None,
    seeds_file: str = None,
    test_packets: bool = None,
) -> List:
    """Run one independent campaign for each transport."""
    logger.info("\n" + "=" * 60)
    logger.info("FUZZING CAMPAIGN")
    logger.info("=" * 60)

    output_file = seeds_file if seeds_file else config.SEEDS_OUTPUT_FILE
    test_packets = test_packets if test_packets is not None else config.TEST_PACKETS

    all_specs = specs

    if target_protocols:
        specs = {k: v for k, v in specs.items() if k in target_protocols}
        logger.info(f"Mutation targets: {list(specs.keys())}")

    tcp_specs = {k: v.for_transport("tcp") for k, v in specs.items() if _get_transport(k, services, all_specs) in ("tcp", "both")}
    udp_specs = {k: v.for_transport("udp") for k, v in specs.items() if _get_transport(k, services, all_specs) in ("udp", "both")}

    allowed_probe_members = _resolve_probe_targets(probe_targets)
    _n_total = len(services)
    _n_allowed = _n_total if allowed_probe_members is None else len(allowed_probe_members)
    logger.info(
        f"Probe targets: {_n_allowed}/{_n_total} SERVICES members "
        f"(mutation targets: TCP={len(tcp_specs)} UDP={len(udp_specs)})"
    )

    _missing = [k for k in list(tcp_specs) + list(udp_specs)
                if k not in services
                or (allowed_probe_members is not None and k not in allowed_probe_members)]
    if _missing:
        logger.warning(
            f"Probe fleet missing baseline member(s) for mutation targets: {_missing}. "
            f"These targets will yield no candidates. "
            f"Add the cluster name (e.g. 'ssh') or the baseline key to --probe-targets."
        )

    all_candidates = []
    all_mutations = []
    all_candidate_stream_entries = []

    def _run_one_transport_group(group_specs, group_services, transport_label):
        """Run a campaign over the complete available same-transport fleet."""
        if not group_specs:
            return [], []

        logger.info(f"\n{'='*60}")
        logger.info(f"TRANSPORT GROUP: {transport_label} ({len(group_specs)} protocols)")
        logger.info(f"{'='*60}")

        fp_threshold, seed_threshold = _scaled_thresholds(len(group_services))
        logger.info(
            f"  Legacy/static thresholds (member_count={len(group_services)}): "
            f"fp={fp_threshold}, seed={seed_threshold}"
        )

        orchestrator = FuzzingOrchestrator(
            protocol_specs=group_specs,
            services=group_services,
            max_iterations=config.MAX_ITERATIONS,
            max_mutations_per_seed=config.ADAPTIVE_FUZZ_INITIAL,
            seeds_file=output_file,
            test_packets=test_packets,
            fingerprint_collection_threshold=fp_threshold,
            seed_selection_threshold=seed_threshold,
            max_seeds_per_group=getattr(config, 'MAX_SEEDS_PER_RESPONSE_GROUP', 5),
            seed_selection_strategy=getattr(config, 'SEED_SELECTION_STRATEGY', 'hash'),
            transport=transport_label.lower()
        )

        results = orchestrator.run_campaign(
            initial_seeds=initial_seeds,
            protocol_names=list(group_specs.keys()),
            num_workers=getattr(config, 'CONCURRENT_WORKERS', 4)
        )
        all_candidate_stream_entries.extend(
            getattr(orchestrator, "candidate_stream_entries", []))

        _malloc_trim()

        if test_packets:
            return results, []
        return [], results

    if tcp_specs:
        tcp_services = {
            name: svc for name, svc in services.items()
            if _get_transport(name, services, all_specs) in ("tcp", "both")
            and (allowed_probe_members is None or name in allowed_probe_members)
        }
        cands, muts = _run_one_transport_group(tcp_specs, tcp_services, "TCP")
        all_candidates.extend(cands)
        all_mutations.extend(muts)

    if udp_specs:
        udp_services = {}
        for name, svc in services.items():
            if (_get_transport(name, services, all_specs) in ("udp", "both")
                    and (allowed_probe_members is None or name in allowed_probe_members)):
                if len(svc) >= 2:
                    udp_services[name] = (svc[0], svc[1], "udp")
                else:
                    udp_services[name] = svc
        cands, muts = _run_one_transport_group(udp_specs, udp_services, "UDP")
        all_candidates.extend(cands)
        all_mutations.extend(muts)

    if not tcp_specs and not udp_specs:
        logger.warning("No specs loaded, nothing to fuzz")
        return []

    if test_packets:
        if (getattr(config, "CANDIDATE_STREAM_ENABLED", False)
                and all_candidate_stream_entries):
            stats = export_candidate_streams(
                all_candidate_stream_entries,
                config.OUTPUT_FILE,
                max_per_pattern=int(getattr(
                    config, "MAX_FINGERPRINTS_PER_RESPONSE_PATTERN", 1)),
            )
            logger.info(
                "[CANDIDATE-STREAM] exported %d/%d records from %d files to %s",
                stats["written_records"], stats["read_records"],
                stats["source_files"], stats["output_path"],
            )
        logger.info(f"\n{'='*60}")
        logger.info(
            f"All transport groups complete. In-memory candidates: "
            f"{len(all_candidates)}, stream files: "
            f"{len(all_candidate_stream_entries)}")
        logger.info(f"{'='*60}")
        return all_candidates
    logger.info(f"\n{'='*60}")
    logger.info(f"All transport groups complete. Total mutations: {len(all_mutations)}")
    logger.info(f"{'='*60}")
    return all_mutations

def print_summary(candidates: List[FingerprintCandidate]):
    """Summarize candidates by observed service sets."""
    logger.info("\n" + "=" * 60)
    logger.info("SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Total candidates found: {len(candidates)}")

    by_service_count = {}
    for c in candidates:
        count = len(c.observed_clusters)
        by_service_count[count] = by_service_count.get(count, 0) + 1

    logger.info("\nCandidate records by observed cluster count:")
    for count, num in sorted(by_service_count.items()):
        logger.info(f"  {count} clusters: {num} records")

    from collections import Counter
    group_counter = Counter()
    for c in candidates:
        group_key = tuple(sorted(c.observed_clusters))
        group_counter[group_key] += 1

    logger.info("\nCandidate records by observed cluster set:")
    for group, count in group_counter.most_common(20):
        logger.info(f"  {list(group)}: {count} candidates")

    if candidates:
        logger.info("\nSample candidates:")
        for i, c in enumerate(candidates[:5]):
            logger.info(f"  [{i+1}] Packet: {c.packet.hex()[:32]}...")
            logger.info(
                f"       Responding members: "
                f"{[r.service_name for r in c.responses]}"
            )

def export_results(candidates: List[FingerprintCandidate], filepath: str):
    """Export nested service/implementation responses with phase and mutation-target metadata."""
    objective_version = getattr(config, "OBJECTIVE_VERSION", "")
    weights_hash = weight_config_hash(
        prevalence_alpha=float(
            getattr(config, "SERVICE_WEIGHT_PREVALENCE_ALPHA", 0.7)
        )
    )
    records = [
        candidate_to_nested_dict(
            c.packet, c.responses,
            c.mutation_target or None,
            c.iteration, c.transport,
            candidate_type=c.candidate_type,
            objective_version=objective_version,
            weight_config_hash=weights_hash,
        )
        for c in candidates
    ]

    with open(filepath, 'w') as f:
        json.dump(records, f, indent=2)

    logger.info(f"Exported {len(records)} candidate records to {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="Protocol Fuzzer - Edit config.py to configure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick Usage:
  mamba run -n protocol_fuzzer python main.py                    # Run with default config
  mamba run -n protocol_fuzzer python main.py --verbose          # Detailed output
  mamba run -n protocol_fuzzer python main.py --list             # List available specs

Configuration:
  All settings are in config.py. Edit it to change:
  - Services to fuzz (add spec files to protocol/specs/)
  - Target services (host/port)
  - Seed packets
  - Fuzzing parameters

Adding New Services:
  1. Create protocol/specs/{service}.py
  2. Define class that inherits UnifiedProtocolSpec
  3. Run mamba run -n protocol_fuzzer python main.py
        """
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available protocol specs"
    )

    parser.add_argument(
        "--services",
        help="Override services with JSON config file"
    )

    parser.add_argument(
        "--protocols",
        nargs="+",
        help="Specific protocols to fuzz"
    )

    parser.add_argument(
        "--probe-targets",
        nargs="+",
        default=None,
        help="Local server targets to probe (one payload across services). Default: ALL SERVICES members "
             "(incl. variants). Accepts cluster names (e.g. 'ssh' → all 5 ssh-* members) "
             "or explicit member keys (e.g. 'ssh-dropbear'). Overrides config.PROBE_TARGETS."
    )

    parser.add_argument(
        "--seeds-input",
        help="Override input seed file (format: hex,service1;service2;...)"
    )

    parser.add_argument(
        "--seeds-output",
        help="Override output seed file for candidates"
    )

    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Generate mutations without testing (offline mode, save all mutations to file)"
    )

    args = parser.parse_args()

    if args.list:
        available = list_available_specs()
        print("\nAvailable protocol specs:")
        for s in available:
            print(f"  - {s}")
        print(f"\nTotal: {len(available)}")
        return

    _configure_logging(verbose=args.verbose)

    logger.info("Protocol Fuzzer - Starting...")

    logger.info("\n" + "="*60)
    logger.info("STEP 1/4: Loading Protocol Specs")
    logger.info("="*60)
    logger.info(f"Loading specs from: {config.PROTOCOL_SPECS_DIR}")
    specs = load_specs_from_directory(
        config.PROTOCOL_SPECS_DIR,
        config.SERVICES_TO_FUZZ
    )

    if not specs:
        available = list_available_specs()
        logger.error("No protocol specs loaded!")
        if available:
            logger.info(f"Available specs: {available}")
            logger.info("Set SERVICES_TO_FUZZ in config.py or leave empty to load all")
        sys.exit(1)

    # ========== STEP 2: Load Services ==========
    logger.info("\n" + "="*60)
    logger.info("STEP 2/4: Loading Service Configuration")
    logger.info("="*60)
    if args.services:
        services = load_services_from_file(args.services)
        logger.info(f"Loaded services from: {args.services}")
    else:
        services = load_services_from_config()
        logger.info("Using services from config.py")

    logical_clusters = {config.cluster_of(name) for name in services}
    logger.info(
        f"Loaded {len(services)} service endpoints across "
        f"{len(logical_clusters)} logical clusters")
    logger.debug(f"Service endpoints: {list(services.keys())}")

    # ========== STEP 3: Load Seeds ==========
    logger.info("\n" + "="*60)
    logger.info("STEP 3/4: Loading Seeds")
    logger.info("="*60)
    initial_seeds = load_seeds(seeds_file=args.seeds_input)

    if not initial_seeds:
        logger.error("No seeds available! Exiting.")
        sys.exit(1)

    # ========== STEP 4: Fuzzing ==========
    logger.info("\n" + "="*60)
    logger.info("STEP 4/4: Starting Fuzzing Campaign")
    logger.info("="*60)
    
    if args.no_test:
        test_packets = False
        logger.info("Mode: Offline (mutation generation only)")
    else:
        test_packets = config.TEST_PACKETS
        logger.info(f"Mode: {'Online (testing against real services)' if test_packets else 'Offline (mutation generation only)'}")

    logger.info(f"Configuration:")
    logger.info(f"  - Max iterations: {config.MAX_ITERATIONS}")
    logger.info(f"  - Max mutations per seed: {config.ADAPTIVE_FUZZ_INITIAL}")
    logger.info(f"  - Concurrent workers: {config.CONCURRENT_WORKERS}")
    logger.info(f"  - Mutation targets: {args.protocols or list(specs.keys())}")
    logger.info(
        f"  - Objective: {config.OBJECTIVE_VERSION} "
        f"(reward_mode={config.REWARD_MODE}, "
        f"credit={config.MULTI_FIELD_CREDIT_MODE}, "
        f"bandit_state={os.path.basename(config.RL_STATE_FILE)}, "
        f"compat_prior={getattr(config, 'COMPATIBILITY_PRIOR_MODE', 'none')})"
    )

    results = run_fuzzing(
        specs=specs,
        services=services,
        initial_seeds=initial_seeds,
        target_protocols=args.protocols,
        probe_targets=args.probe_targets if args.probe_targets is not None else config.PROBE_TARGETS,
        seeds_file=args.seeds_output,
        test_packets=test_packets,
    )

    if test_packets:
        candidates = results
    else:
        
        mutations = results
        logger.info(f"\nGenerated {len(mutations)} total mutations")

        if config.SEEDS_OUTPUT_FILE:
            save_seeds_to_file(mutations, config.SEEDS_OUTPUT_FILE)
            logger.info(f"Saved all mutations to {config.SEEDS_OUTPUT_FILE}")

        candidates = []

    print_summary(candidates)

    if candidates:
        
        original_count = len(candidates)
        candidates = deduplicate_candidates(
            candidates,
            max_per_pattern=config.MAX_FINGERPRINTS_PER_RESPONSE_PATTERN,
            strategy=config.SEED_SELECTION_STRATEGY
        )
        if len(candidates) < original_count:
            logger.info(f"Deduplicated: {original_count} -> {len(candidates)} candidate records "
                       f"(kept {len(candidates)/original_count*100:.1f}%)")

        export_results(candidates, config.OUTPUT_FILE)

    logger.info("\nDone!")

if __name__ == "__main__":
    main()
