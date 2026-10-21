#!/usr/bin/env bash
# Build the two shared bases and start the available paper configurations.
set -euo pipefail
cd "$(dirname "$0")"
docker build -t protocol-base-ubuntu:latest base/ubuntu
docker build -t protocol-base-python:latest base/python
docker compose --profile all --profile alt up --build -d "$@"
