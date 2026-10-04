#!/usr/bin/env sh
# Start PRAMAN on a managed web host.
#
# The platform terminates public TLS before forwarding to this process. PRAMAN
# intentionally still speaks ordinary HTTP internally, just as it does behind
# deploy/nginx/praman.conf on a VM. HOST is explicit here because the application
# defaults to loopback for safe offline/local use.
set -eu

export HOST="${HOST:-0.0.0.0}"
python scripts/bootstrap_user.py
exec python scripts/serve.py
