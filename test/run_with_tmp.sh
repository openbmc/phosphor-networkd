#!/bin/bash
TMPDIR="$(mktemp -d)" || exit
trap 'rm -rf -- "$TMPDIR"' EXIT
export TMPDIR
echo "Exec $* with TMPDIR=$TMPDIR" >&2
"$@"
