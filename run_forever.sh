#!/usr/bin/env bash
set -euo pipefail

# run forever, even if we fail
while true; do
    git pull
    npm ci --no-audit --no-fund
    npm run build:css
    go build -tags release -o mochi
    if ./mochi; then
        printf '%s\n' 'Mochi exited; restarting after one second.'
    else
        printf '%s\n' 'Mochi failed; restarting after one second.' >&2
    fi
    sleep 1
done
