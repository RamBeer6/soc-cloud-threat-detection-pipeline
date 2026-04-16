#!/usr/bin/env bash

set -euo pipefail

python src/main.py run --count 200 --output logs/events.jsonl --alerts-output logs/alerts.log --seed 42
