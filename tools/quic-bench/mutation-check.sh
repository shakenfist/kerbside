#!/bin/bash
# Mutation check for quic-bench's unit tests.
#
# `make test` passing says the tests ran, not that they would have noticed
# anything. This breaks one property per mutation and requires the named test
# to fail; a mutation that survives means that test is decoration. Run it after
# changing src/ or the tests, and expect every mutant killed.
#
# Three notes earned the hard way. The first: the fixture for the nearest-rank
# test used 100 samples, where every quantile lands on an integer rank, so
# rounding down was indistinguishable from rounding up and the mutation
# survived. The second: `percentile`'s clamp has a reachable half and an
# unreachable one -- its lower bound stops a quantile of 0 underflowing, while
# its upper bound cannot be reached by any quantile of 1.0 or less, so only the
# lower bound is mutated.
#
# The third: the segmentation-offload mutant is only observable on a host whose
# UDP socket offers more than one transmit segment, because where it offers one
# the on and off configurations produce the same number. The hosts this bench
# has run on offer 64. On one that does not, that mutant would survive, and the
# right reading is that the configuration is unobservable there rather than that
# the test is decoration.
#
# Files are restored from a pristine copy, never with `git checkout <dir>`,
# which would discard uncommitted work in that directory. Each mutant runs
# under timeout, and a timeout counts as killed.
#
# Every mutation is an exact source match, so reformatting src/ turns a mutant
# into one that cannot be applied. An unappliable mutant is unverified, not
# killed, so skips are counted and fail the run alongside survivors.
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

killed=0 survived=0 skipped=0
mutate() {
    local name="$1" expect="$2" file="$3" from="$4" to="$5"
    restore
    if ! python3 -I - "$CRATE/src/$file" "$from" "$to" <<'MUTATE'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if text.count(old) != 1:
    sys.exit(f'MUTATION TARGET NOT UNIQUE in {path}: {text.count(old)} matches')
open(path, 'w').write(text.replace(old, new))
MUTATE
    then
        echo "SKIPPED  ${name}: could not apply"
        skipped=$((skipped+1))
        return
    fi
    # Keep the test run's exit status: a mutant that hangs by design is killed
    # when timeout cuts it off, and that is 124 from timeout rather than silence
    # on stdout. Scoring the kill on empty output instead would score anything
    # that stopped the suite from running at all -- an absent docker daemon, a
    # missing image, a bad make invocation -- as a kill, which is the same
    # vacuous pass as a mutant that would not apply.
    local test_rc=0
    if out="$(cd "${CRATE}" && timeout 600 make test 2>&1)"; then
        test_rc=0
    else
        test_rc=$?
    fi
    # The kill has to be the named test failing. A panic anywhere else in the
    # suite, and a mutant that stops the crate compiling, both end the run
    # without showing that this property is defended, so they are unverified
    # rather than killed -- which fails the gate, as a skip does. Every mutant
    # here is killed by its named test today, so nothing relies on the looser
    # reading; a future mutant that cannot be expressed without breaking the
    # build is a mutant to rewrite, not to credit.
    if printf '%s' "${out}" | grep -qE "^test tests::${expect} \.\.\. FAILED" \
        || printf '%s' "${out}" | grep -qE "thread 'tests::${expect}' panicked"; then
        echo "KILLED   ${name} -> ${expect}"
        killed=$((killed+1))
    elif printf '%s' "${out}" | grep -q 'error\[E'; then
        echo "SKIPPED  ${name}: would not compile, so ${expect} never ran; unverified"
        skipped=$((skipped+1))
    elif printf '%s' "${out}" | grep -q 'panicked'; then
        echo "SKIPPED  ${name}: something panicked, but not ${expect}; unverified"
        skipped=$((skipped+1))
    elif [ "${test_rc}" -eq 124 ]; then
        echo "KILLED   ${name} -> timed out"
        killed=$((killed+1))
    elif [ -z "${out}" ]; then
        echo "SKIPPED  ${name}: the test run printed nothing and exited ${test_rc}, so the"
        echo "         property was never exercised; unverified, not killed"
        skipped=$((skipped+1))
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

mutate 'header role discarded' 'a_header_round_trips_its_role_and_size' \
    workload.rs 'Ok((head[0], size))' 'Ok((ROLE_IDLE, size))'

mutate 'short header read not checked' 'a_truncated_header_is_an_error_not_a_default' \
    workload.rs 'stream.read_exact(&mut head).await?;' 'let _ = stream.read_exact(&mut head).await;'

mutate 'header size written big-endian' \
    'an_encoded_header_decodes_to_the_role_and_size_it_carried' \
    workload.rs '&(size as u32).to_le_bytes()' '&(size as u32).to_be_bytes()'

mutate 'header size ceiling exclusive' \
    'an_encoded_header_decodes_to_the_role_and_size_it_carried' \
    workload.rs 'size > 8 * 1024 * 1024' 'size >= 8 * 1024 * 1024'

mutate 'warmup boundary excludes its own first sample' \
    'only_samples_at_or_after_the_warmup_boundary_are_measured' main.rs \
    '.filter(|s| s.offset_ms >= warmup_ms)' '.filter(|s| s.offset_ms > warmup_ms)'

mutate 'warmup boundary inverted' \
    'only_samples_at_or_after_the_warmup_boundary_are_measured' main.rs \
    '.filter(|s| s.offset_ms >= warmup_ms)' '.filter(|s| s.offset_ms < warmup_ms)'

mutate 'warmup read as seconds against a boundary in milliseconds' \
    'only_samples_at_or_after_the_warmup_boundary_are_measured' main.rs \
    'work.warmup.as_secs_f64() * 1000.0' 'work.warmup.as_secs_f64() * 1.0'

mutate 'warmup discards nothing' \
    'a_run_whose_samples_all_fall_in_the_warmup_publishes_no_percentiles' main.rs \
    '.filter(|s| s.offset_ms >= warmup_ms)' '.filter(|_s| true)'

mutate 'steady samples left in arrival order' \
    'the_published_percentiles_are_over_sorted_samples' main.rs \
    'steady.sort_unstable();' 'steady.sort_by_key(|_| 0);'

mutate 'the quic arm and the tcp arm labelled the wrong way round' \
    'the_results_name_the_congestion_controller_only_for_the_quic_arm' main.rs \
    'if transport == Transport::Quic' 'if transport == Transport::Tcp'

mutate 'one connection short of a session' \
    'the_tcp_arm_opens_one_connection_per_channel_with_nagle_off' tcp.rs \
    'for _ in 0..channels {' 'for _ in 1..channels {'

mutate 'nagle left on for the client channels' \
    'the_tcp_arm_opens_one_connection_per_channel_with_nagle_off' tcp.rs \
    '        let stream = TcpStream::connect(server).await?;
        stream.set_nodelay(true)?;' '        let stream = TcpStream::connect(server).await?;
        stream.set_nodelay(false)?;'

mutate 'the no-gso socket reports a batch' \
    'the_no_gso_socket_reports_one_segment_and_delegates_everything_else' nogso.rs \
    'fn max_transmit_segments(&self) -> usize {
        1
    }' 'fn max_transmit_segments(&self) -> usize {
        2
    }'

mutate 'the no-gso socket answers for the inner one' \
    'the_no_gso_socket_reports_one_segment_and_delegates_everything_else' nogso.rs \
    'fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }' 'fn may_fragment(&self) -> bool {
        !self.inner.may_fragment()
    }'

mutate 'the gso control flag reversed' \
    'a_quic_endpoint_sends_one_datagram_per_write_unless_gso_is_allowed' quic.rs \
    '    let socket: Arc<dyn quinn::AsyncUdpSocket> = if allow_gso {
        wrapped
    } else {
        Arc::new(NoGso::new(wrapped))
    };' '    let socket: Arc<dyn quinn::AsyncUdpSocket> = if allow_gso {
        Arc::new(NoGso::new(wrapped))
    } else {
        wrapped
    };'

mutate 'an empty certificate chain accepted' \
    'a_certificate_file_is_read_whole_and_one_with_no_certificate_is_refused' quic.rs \
    '    if certs.is_empty() {' '    if false {'

mutate 'only the leaf certificate read' \
    'a_certificate_file_is_read_whole_and_one_with_no_certificate_is_refused' quic.rs \
    'rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?' \
    'rustls_pemfile::certs(&mut reader)
        .take(1)
        .collect::<Result<Vec<_>, _>>()?'

mutate 'a missing private key becomes an empty one' \
    'a_key_file_is_read_and_one_with_no_private_key_is_refused' quic.rs \
    '    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| format!("no private key in {}", path.display()).into())' \
    '    Ok(rustls_pemfile::private_key(&mut reader)?
        .unwrap_or(PrivateKeyDer::Pkcs8(Vec::<u8>::new().into())))'


echo
echo "killed ${killed}, survived ${survived}, skipped ${skipped}"
[ "${survived}" -eq 0 ] && [ "${skipped}" -eq 0 ]
