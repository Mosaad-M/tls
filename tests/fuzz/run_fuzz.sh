#!/usr/bin/env bash
# Build tests/fuzz/fuzz_parsers.mojo once, then fuzz or replay.
#
#   run_fuzz.sh <iterations> [seed ...]   fuzz every target with each seed
#                                         (default seed 1). FUZZ_TARGETS="a b"
#                                         restricts the targets.
#   run_fuzz.sh replay                    replay every saved crasher; fails if
#                                         any input aborts the process again.
#
# A fuzzing run that aborts (a Mojo bounds-check failure, i.e. an out-of-bounds
# read) saves the input as tests/fuzz/crashers/<target>-<sha1 prefix>.bin and
# makes the script fail. Commit that file with the fix: replay mode, part of
# `pixi run test`, keeps it fixed. FUZZ_BIN reuses an existing build.
#
# Run from the repo root inside the pixi environment (pixi run fuzz / test-fuzz-regressions).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CRASHERS="$ROOT/tests/fuzz/crashers"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="${FUZZ_BIN:-}"
if [ -z "$BIN" ]; then
    BIN="$WORK/fuzz_parsers"
    echo "building fuzz_parsers..."
    (cd "$ROOT" && mojo build -I . -I tests tests/fuzz/fuzz_parsers.mojo -o "$BIN") || exit 1
fi
TARGETS="${FUZZ_TARGETS:-$("$BIN" list)}"

# The abort reason (Mojo prints the assertion before the stack trace)
why() { echo "$1" | grep -m2 -iE "assert|out of bounds|error" || echo "$1" | tail -3; }

if [ "${1:-}" = "replay" ]; then
    fails=0; n=0
    for f in "$CRASHERS"/*.bin; do
        [ -e "$f" ] || continue
        name="$(basename "$f")"
        target="${name%%-*}"
        if ! printf '%s\n' $TARGETS | grep -qx "$target"; then
            echo "  FAIL: $name - unknown target $target"; fails=$((fails + 1)); continue
        fi
        if out="$("$BIN" replay "$target" "$f" 2>&1)"; then
            echo "  PASS: $name - $(echo "$out" | tail -1)"
        else
            echo "  FAIL: $name - process aborted:"; why "$out"
            fails=$((fails + 1))
        fi
        n=$((n + 1))
    done
    echo "Results: $((n - fails)) passed, $fails failed"
    [ "$n" -gt 0 ] && [ "$fails" -eq 0 ]
    exit
fi

ITER="${1:?usage: run_fuzz.sh <iterations> [seed ...] | replay}"
shift
SEEDS="${*:-1}"
crashes=0
for seed in $SEEDS; do
    for t in $TARGETS; do
        start=$SECONDS
        if out="$("$BIN" "$t" "$seed" "$ITER" "$WORK/current.bin" 2>&1)"; then
            echo "$(echo "$out" | tail -1) [$((SECONDS - start))s]"
        else
            mkdir -p "$CRASHERS"
            dest="$CRASHERS/$t-$(shasum "$WORK/current.bin" | cut -c1-12).bin"
            cp "$WORK/current.bin" "$dest"
            echo "CRASH: target $t seed $seed - input saved to ${dest#$ROOT/}"
            why "$out"
            crashes=$((crashes + 1))
        fi
    done
done
[ "$crashes" -eq 0 ] || { echo "$crashes crash(es)"; exit 1; }
echo "all targets clean"
