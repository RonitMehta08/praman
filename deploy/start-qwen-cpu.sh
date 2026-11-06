#!/usr/bin/env sh
# Optional VM-side llama.cpp server, independent of the audit service.
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SERVER="${PRAMAN_LLAMA_SERVER:-$PROJECT_ROOT/vendor/llama-cpp-linux/build/bin/llama-server}"
MODEL="${PRAMAN_QWEN_MODEL:-$PROJECT_ROOT/data/models/Qwen_Qwen3-4B-Instruct-2507-Q4_K_M.gguf}"
if [ ! -x "$SERVER" ]; then
    printf '%s\n' "Linux llama-server missing at $SERVER. Run Step 18c in MANUAL_COMMANDS.md." >&2
    exit 1
fi
if [ ! -r "$MODEL" ]; then
    printf '%s\n' "Qwen GGUF missing at $MODEL. Run Step 18c in MANUAL_COMMANDS.md." >&2
    exit 1
fi
# One slot and no saved prompt cache bound memory on the initial 8 GiB VM.
# Flags are from llama.cpp b10610; this profile requires no CUDA installation.
exec "$SERVER" --model "$MODEL" --ctx-size 4096 --parallel 1 \
    --threads "${PRAMAN_QWEN_THREADS:-2}" --device none --n-gpu-layers 0 \
    --cache-ram 0 --host 127.0.0.1 --port 8080
