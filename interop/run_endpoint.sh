#!/bin/sh

# Setup network routing via the base image's setup script.
# Ignore errors (compliance check runs without a real network).
/setup.sh 2>/dev/null || true

if [ "$ROLE" = "server" ]; then
  exec /server
else
  exec /client "$@"
fi
