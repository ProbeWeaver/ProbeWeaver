"""Classifier CLI: train a corpus-bound RF or export it to Go."""
import sys


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"train", "export"}:
        print("Usage: mamba run -n protocol_fuzzer python -m fingerprint {train|export} --help")
        return 0 if "--help" in sys.argv else 2
    command = sys.argv.pop(1)
    if command == "train":
        from scripts.train_tier2_rf import main as run
    else:
        from fingerprint.export_to_go import main as run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
