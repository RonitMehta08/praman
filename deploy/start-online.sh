#!/usr/bin/env sh
# Start PRAMAN on a managed web host.
#
# The platform terminates public TLS before forwarding to this process. PRAMAN
# intentionally still speaks ordinary HTTP internally, just as it does behind
# deploy/nginx/praman.conf on a VM. HOST is explicit here because the application
# defaults to loopback for safe offline/local use.
set -eu

export HOST="${HOST:-0.0.0.0}"
export SENTINEL_AI_BACKEND="${SENTINEL_AI_BACKEND:-classifiers}"
export PRAMAN_SIGNUP_ENABLED="${PRAMAN_SIGNUP_ENABLED:-true}"
export HF_HUB_OFFLINE="${HF_HUB_OFFLINE:-1}"
export TRANSFORMERS_OFFLINE="${TRANSFORMERS_OFFLINE:-1}"
python scripts/bootstrap_user.py
exec python scripts/serve.py
