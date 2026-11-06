#!/usr/bin/env sh
# systemd supplies the environment; nginx terminates public HTTPS.
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PROJECT_ROOT"
PYTHON="$PROJECT_ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    printf '%s\n' 'VM virtual environment missing. Run Step 18 in MANUAL_COMMANDS.md.' >&2
    exit 1
fi
export HOST=127.0.0.1
export PORT=8012
export PYTHONUTF8=1
export SENTINEL_AI_BACKEND="${SENTINEL_AI_BACKEND:-classifiers}"
export PRAMAN_SIGNUP_ENABLED="${PRAMAN_SIGNUP_ENABLED:-true}"
export HF_HUB_OFFLINE="${HF_HUB_OFFLINE:-1}"
export TRANSFORMERS_OFFLINE="${TRANSFORMERS_OFFLINE:-1}"
"$PYTHON" scripts/bootstrap_user.py
exec "$PYTHON" scripts/serve.py
