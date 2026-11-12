#!/bin/bash
# Mutation check for quic-bench's unit tests.
#
# `make test` passing says the tests ran, not that they would have noticed
# anything. This breaks one property per mutation and requires the named test
# to fail; a mutation that survives means that test is decoration. Run it after
# changing src/ or the tests, and expect every mutant killed.
#
# Two notes earned the hard way. The first fixture for the nearest-rank test
# used 100 samples, where every quantile lands on an integer rank, so rounding
# down was indistinguishable from rounding up and the mutation survived. And
# `percentile`'s clamp has a reachable half and an unreachable one: its lower
# bound stops a quantile of 0 underflowing, while its upper bound cannot be
# reached by any quantile of 1.0 or less, so only the lower bound is mutated.
#
# Files are restored from a pristine copy, never with `git checkout <dir>`,
# which would discard uncommitted work in that directory. Each mutant runs
# under timeout, and a timeout counts as killed.
set -u

CRATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE="$(mktemp -d)"
cp -a "${CRATE}/src" "${SAFE}/src"

# Restore, then stamp the files as modified now.
#
# cargo decides what to rebuild from mtimes, and `cp -a` preserves the
# original's -- which is older than the artifact built from the mutant that
# was just tested. Without the touch, cargo considers the restored source
# fresh, skips the rebuild, and the next `make test` runs the last mutant's
# binary against correct code: a failure that looks like a broken tree and is
# really a stale one. Found exactly that way.
restore() {
    rm -rf "${CRATE}/src"
    cp -a "${SAFE}/src" "${CRATE}/src"
    find "${CRATE}/src" -type f -exec touch {} +
}
trap 'restore; rm -rf "${SAFE}"' EXIT

killed=0 survived=0
mutate() {
    local name="$1" expect="$2" file="$3" from="$4" to="$5"
    restore
    if ! python3 - "$CRATE/src/$file" "$from" "$to" <<'MUTATE'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if text.count(old) != 1:
    sys.exit(f'MUTATION TARGET NOT UNIQUE in {path}: {text.count(old)} matches')
open(path, 'w').write(text.replace(old, new))
MUTATE
    then
        echo "SKIP  ${name}: could not apply"
        return
    fi
    out="$(cd "${CRATE}" && timeout 600 make test 2>&1)"
    if printf '%s' "${out}" | grep -qE "^test tests::${expect} \.\.\. FAILED|panicked"; then
        echo "KILLED   ${name} -> ${expect}"
        killed=$((killed+1))
    elif printf '%s' "${out}" | grep -q 'error\[E'; then
        echo "KILLED   ${name} -> would not compile"
        killed=$((killed+1))
    elif [ -z "${out}" ]; then
        echo "KILLED   ${name} -> timed out"
        killed=$((killed+1))
    else
        echo "SURVIVED ${name}: expected ${expect} to fail"
        printf '%s\n' "${out}" | grep -E '^test result|^test tests' | head -12
        survived=$((survived+1))
    fi
}

mutate 'percentile of empty returns zero' 'percentile_of_nothing_is_none' main.rs \
    'if sorted.is_empty() {
        return None;
    }' 'if sorted.is_empty() {
        return Some(0);
    }'

mutate 'percentile rounds down' 'percentile_is_nearest_rank' main.rs \
    '(quantile * sorted.len() as f64).ceil()' '(quantile * sorted.len() as f64).floor()'

mutate 'percentile does not clamp the bottom' 'percentile_never_runs_off_the_bottom' main.rs \
    'sorted[rank.clamp(1, sorted.len()) - 1]' 'sorted[rank - 1]'

mutate 'throughput without a zero guard' \
    'throughput_without_a_steady_window_is_zero_not_a_division_by_zero' workload.rs \
    'if self.steady_secs <= 0.0 {
            return 0.0;
        }' 'if false {
            return 0.0;
        }'

mutate 'throughput counts warmup bytes' 'throughput_is_megabits_of_the_steady_bytes_only' \
    workload.rs '(self.bytes_steady as f64 * 8.0)' '(self.bytes_total as f64 * 8.0)'

mutate 'bulk and interactive channels swapped' 'the_first_two_channels_are_the_measured_ones' \
    workload.rs '        0 => ROLE_BULK,
        1 => ROLE_INTERACTIVE,' '        0 => ROLE_INTERACTIVE,
        1 => ROLE_BULK,'

mutate 'header size validation removed' 'a_header_claiming_an_implausible_size_is_refused' \
    workload.rs 'if size == 0 || size > 8 * 1024 * 1024 {' 'if false {'

echo
echo "killed ${killed}, survived ${survived}"
[ "${survived}" -eq 0 ]
