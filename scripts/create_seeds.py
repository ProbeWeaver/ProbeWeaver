"""Create fresh nominal seeds from the distributed bounded profiles."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from protocol import specs

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('seeds.txt'))
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; choose a fresh path')
    rows = []
    for name in specs.__all__:
        spec = getattr(specs, name)()
        # Seeds are source packets; mutation uses the target transport profile.
        rows.append(spec.build_seed().hex())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(dict.fromkeys(rows)) + '\n')
    print(f'Created {len(set(rows))} nominal seeds at {args.output}')

if __name__ == '__main__':
    main()
