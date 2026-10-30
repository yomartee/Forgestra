#!/bin/bash
# Deny-only compatibility probe; no installer recipe is distributed.
printf '%s\n' 'BLOCKED: legacy execution is unavailable.' >&2
exit 1
