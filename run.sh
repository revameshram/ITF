#!/usr/bin/env sh
# AegisVision - Linux/macOS launcher
cd "$(dirname "$0")"
[ -f .venv/bin/activate ] && . .venv/bin/activate
python3 -m backend.main --open "$@"
