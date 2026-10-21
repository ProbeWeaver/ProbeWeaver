"""Run the fixed ranked sequence against explicitly supplied endpoints."""
import argparse
import ipaddress
import json
from pathlib import Path
from sequence import run_ours_target

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='IP address of an authorized target')
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--transport', choices=['tcp', 'udp'], default='tcp')
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--output', type=Path, default=Path('outputs/scan'))
    args = parser.parse_args()
    ipaddress.ip_address(args.host)
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error('port must be 1..65535 and timeout must be positive')
    root = Path(__file__).resolve().parent
    if not (root / 'pw-scanner').is_file():
        parser.error('build the scanner first with bash PW_Scanner/build.sh')
    target = {'target_id': 'target', 'endpoint': {'ip': args.host, 'port': args.port,
                                                'transport': args.transport}}
    result = run_ours_target(target, binary=root / 'pw-scanner', rules=root / 'rules.json',
                             probe_set=root.parent / 'probes' / f'selected_{args.transport}.json',
                             raw_dir=args.output, timeout_seconds=args.timeout,
                             process_timeout=max(15, args.timeout * 4), use_ml=True)
    labels = result['raw_labels']
    # Preserve ambiguity: removing an excluded label must not create a unique result.
    excluded = {'smtp', 'lpd', 'openvpn'}
    if excluded.intersection(labels):
        result['outcome'] = 'unknown'
        result['labels'] = []
    else:
        result['labels'] = labels
        if len(labels) > 1:
            result['outcome'] = 'ambiguous'
    print(json.dumps(result, indent=2))
    return 1 if result['outcome'] == 'tool_error' else 0

if __name__ == '__main__':
    raise SystemExit(main())
