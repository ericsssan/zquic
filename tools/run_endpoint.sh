#!/bin/sh
set -e

# Setup network routing via the base image's setup script
if [ -f /setup.sh ]; then
  /setup.sh
fi

if [ "$ROLE" = "server" ]; then
  exec /server
else
  exec /client "$@"
fi
