#!/bin/sh
# Read committed kernel snapshots; never swap objects or modify either checkout.
exec python3 "$(dirname "$0")/kernel_gap.py" "$@"
