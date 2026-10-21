#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
go build -trimpath -o pw-scanner ./cmd/pw-scanner
