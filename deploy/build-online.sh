#!/usr/bin/env sh
# Install the audit engine and the shipped CPU classifiers, then load-check them.
set -eu
python -m pip install -r requirements.lock.txt
python -m pip install torch==2.13.0+cpu --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements-ai.txt
SENTINEL_AI_BACKEND=classifiers HF_HUB_OFFLINE=1 python scripts/check_ai_runtime.py
