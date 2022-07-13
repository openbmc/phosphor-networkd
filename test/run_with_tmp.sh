#!/bin/bash
TMPDIR="$(mktemp -d --tmpdir "${TMPTMPL-tmp.XXXXXXXXXX}")" || exit
trap 'rm -rf -- "$TMPDIR"' EXIT
export TMPDIR
echo "Exec $* with TMPDIR=$TMPDIR" >&2
"$@"
