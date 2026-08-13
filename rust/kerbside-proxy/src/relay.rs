//! The inspection-first SPICE relay.
//!
//! This relays an authorized client `SpiceStream` to the connected backend
//! (hypervisor) `SpiceStream`, framing each direction by the 6-byte SPICE
//! mini-header (`MessageHeader`). Every complete message is passed through a
//! [`Policy`] before it is forwarded, so this is deliberately NOT an opaque
//! `copy_bidirectional`: that [`Policy`] seam is where L0 (size/rate caps) and
//! L1 (message-type allowlist) firewall enforcement happens.
//!
//! One accepted client connection = one backend channel connection = one
//! relayed SPICE channel (SPICE opens a TCP connection per channel).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::messages::MessageHeader;
use shakenfist_spice_protocol::ChannelType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::pb;
use crate::policy::{Direction, EnforcingPolicy, FirewallPolicy, Policy, Verdict, VerdictTally};
use crate::session::SharedState;

/// Sanity cap on a single framed SPICE message's declared body size.
///
/// An unconditional backstop underneath the policy's own L0 caps: a peer that
/// claims an absurd `message_size` must not make us buffer gigabytes waiting
/// for a body that will never arrive. 16 MiB is generous for any legitimate
/// SPICE message (the largest are image/surface payloads); `EnforcingPolicy`
/// caps most channel/direction pairs well below it.
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// How much we read from the socket per `read` call. The reassembly buffer
/// grows as needed for a single large message; this only bounds one read.
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// Backstop on how long a relay direction may block on a single read with no
/// bytes arriving before we tear the whole relay down.
///
/// This is a RESOURCE guard, not a firewall verdict: it is not subject to
/// warn-only and is not recorded in the verdict tally/metrics. Its job is to
/// stop an authorized-but-silent client (or a wedged hypervisor) from pinning a
/// concurrency permit indefinitely. Client-side TCP keepalive (set in
/// `listen.rs`, mirroring the backend leg) is the PRIMARY dead-peer detector —
/// it tears down a peer that has vanished within ~75 s; this generous 15-minute
/// backstop only catches a peer that keeps the TCP connection alive but sends
/// nothing, without killing a legitimately-idle interactive session. Tunable
/// later once real idle patterns are observed.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Relay the authorized client connection to the connected backend channel.
///
/// Splits both streams into read/write halves and runs two framing pumps
/// concurrently (client->server and server->client), each with its own
/// [`EnforcingPolicy`] instance built from the shared `Arc<FirewallPolicy>` and
/// a single shared [`VerdictTally`] (per-direction policy instances, shared
/// verdict counters). A SPICE channel is a single duplex TCP connection: once
/// EITHER direction ends (EOF, an I/O error, or a policy `Terminate`), the
/// whole session is over, so we `select!` and let the first pump to finish tear
/// the other down (dropping its future).
///
/// After the `select!`, the shared tally is read once and — if any firewall
/// verdict was recorded — a single coalesced summary audit event is emitted for
/// the connection (never one event per blocked message). The tally is shared by
/// `Arc`, so the losing pump's counts survive its dropped future.
///
/// Returns `Ok(())` on normal teardown. Genuine faults (a protocol violation
/// such as an oversized frame, or an I/O error) are logged here; we still
/// return `Ok(())` because the caller deregisters the channel and closes the
/// client either way, and a torn-down socket is not separately actionable.
/// Bytes forwarded on each `Verdict::Forward` are counted via
/// `metrics::add_relayed_bytes`; firewall verdicts are counted via
/// `metrics::record_firewall_verdict` inside the policy.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    state: &SharedState,
    policy: Arc<FirewallPolicy>,
    client: SpiceStream,
    backend: SpiceStream,
    channel_type: ChannelType,
    connection_ref: &str,
    target: &pb::Target,
    cancel: CancellationToken,
) -> Result<()> {
    info!(
        %connection_ref,
        channel_type = channel_type.name(),
        "relay starting"
    );

    let (client_reader, client_writer) = tokio::io::split(client);
    let (backend_reader, backend_writer) = tokio::io::split(backend);

    // Each direction gets its OWN EnforcingPolicy instance, so the allowlist
    // lookup needs no lock on the hot path. Both share the connection's
    // Arc<FirewallPolicy> config and ONE Arc<VerdictTally>, so verdict counts
    // from both directions survive the dropped losing pump for the audit flush.
    let tally = Arc::new(VerdictTally::new());
    let client_to_server = pump(
        client_reader,
        backend_writer,
        EnforcingPolicy::new(
            Arc::clone(&policy),
            Direction::ClientToServer,
            Arc::clone(&tally),
        ),
        Direction::ClientToServer,
        channel_type,
        connection_ref,
    );
    let server_to_client = pump(
        backend_reader,
        client_writer,
        EnforcingPolicy::new(
            Arc::clone(&policy),
            Direction::ServerToClient,
            Arc::clone(&tally),
        ),
        Direction::ServerToClient,
        channel_type,
        connection_ref,
    );

    let result = tokio::select! {
        r = client_to_server => r,
        r = server_to_client => r,
        // The control plane terminated this session. Ending here
        // drops both pump futures, closing the stream halves and disconnecting
        // the client -- the same teardown as a finishing pump.
        () = cancel.cancelled() => {
            // CI-ORACLE: this message text is load-bearing for
            // tools/direct-qemu/verify-terminate-live.sh and
            // tools/ovirt-e2e/drive-console.py; update both if it is
            // reworded.
            info!(
                %connection_ref,
                channel_type = channel_type.name(),
                "session terminated by control plane; ending relay"
            );
            Ok(())
        }
    };

    match &result {
        Ok(()) => info!(
            %connection_ref,
            channel_type = channel_type.name(),
            "relay ended"
        ),
        Err(e) => warn!(
            %connection_ref,
            channel_type = channel_type.name(),
            error = %e,
            "relay ended with error"
        ),
    }

    // Flush a single coalesced firewall-verdict audit event for the whole
    // connection, if anything was recorded. Best-effort: an audit RPC failure
    // is logged, not propagated (the connection is already tearing down).
    if let Some(summary) = tally.summary() {
        if let Err(e) = state
            .rpc
            .record_audit_event(
                &target.source,
                &target.uuid,
                &target.session_id,
                channel_type.name(),
                &state.node_name,
                connection_ref,
                &summary,
            )
            .await
        {
            warn!(%connection_ref, error = %e, "recording firewall-verdict-summary audit event failed");
        }
    }

    // Normal teardown is uniform from the caller's perspective; do not
    // propagate the error (see the doc comment above).
    Ok(())
}

/// The framing pump for one direction.
///
/// Generic over the reader/writer/policy so it is unit-testable with
/// `tokio::io::duplex` and in-memory readers (a `SpiceStream` cannot wrap a
/// duplex). Reads bytes into a reassembly buffer. As soon as a message's
/// 6-byte header is parsed — and BEFORE its body is buffered — it consults
/// [`Policy::check_header`] (L0 size/rate) exactly once per message; a
/// `Terminate` there flushes and ends the pump without ever accumulating the
/// body. Otherwise, for every complete framed message (`MessageHeader` +
/// `message_size` body) present, it consults [`Policy::inspect`] and acts on
/// its [`Verdict`]:
///
/// - [`Verdict::Forward`]: write the ORIGINAL framed bytes (header + body,
///   unchanged — never re-encoded) to `writer`, then advance past them.
/// - [`Verdict::Drop`]: advance past the message without forwarding it.
/// - [`Verdict::Terminate`]: flush and end the pump (which ends the relay).
///
/// Each blocking `read` is bounded by [`IDLE_READ_TIMEOUT`]: on elapse the
/// pump ends cleanly (a resource guard, not a firewall verdict), so a silent
/// peer cannot pin a concurrency permit forever.
///
/// Returns `Ok(())` on clean EOF (or an idle timeout), or `Err` on a protocol
/// violation (an oversized frame) or an underlying I/O error.
async fn pump<R, W, P>(
    mut reader: R,
    mut writer: W,
    mut policy: P,
    dir: Direction,
    channel: ChannelType,
    connection_ref: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    P: Policy,
{
    // Reassembly buffer holding bytes read but not yet fully framed/consumed.
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK_SIZE);
    let mut chunk = vec![0u8; READ_CHUNK_SIZE];
    // Whether the message currently at the FRONT of `buf` (offset 0 after each
    // `drain`) has already had `check_header` run for it. This dedupes the L0
    // header check so a message whose body spans several reads is header-
    // checked exactly once — critical for the rate counter, which must not
    // count one message many times.
    let mut header_checked = false;

    loop {
        let n = match tokio::time::timeout(IDLE_READ_TIMEOUT, reader.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                // Resource guard, not a firewall verdict: end the relay cleanly
                // so a silent peer cannot pin a concurrency permit forever.
                warn!(
                    %connection_ref,
                    channel = channel.name(),
                    timeout_secs = IDLE_READ_TIMEOUT.as_secs(),
                    "relay idle-read timeout; ending relay"
                );
                return Ok(());
            }
        };
        if n == 0 {
            // EOF: no more messages will arrive on this direction. Flush
            // whatever we have already forwarded and end cleanly.
            writer.flush().await?;
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);

        // Drain every complete message currently in the buffer. `consumed`
        // tracks how far we have advanced so we slice without reallocating,
        // then drop the consumed prefix once in a single `drain` below.
        let mut consumed = 0usize;
        loop {
            let available = buf.len() - consumed;
            if available < MessageHeader::SIZE {
                break; // need more bytes for a header
            }

            // Guaranteed >= 6 bytes here, so this parse cannot fail on length.
            let header = MessageHeader::read(&buf[consumed..consumed + MessageHeader::SIZE])?;

            if header.message_size > MAX_MESSAGE_SIZE {
                return Err(anyhow!(
                    "SPICE message size {} exceeds cap {} ({:?}, channel {})",
                    header.message_size,
                    MAX_MESSAGE_SIZE,
                    dir,
                    channel.name()
                ));
            }

            // L0: consult the policy on the header BEFORE buffering the body, so
            // an over-cap or over-rate message is refused without accumulating
            // its body (bounded otherwise only by the absolute guard above).
            // Run exactly once per message via `header_checked`. Only Terminate
            // is actioned here; Forward/Drop both let the relay proceed to
            // buffer the body and call `inspect`.
            if !header_checked {
                header_checked = true;
                if matches!(
                    policy.check_header(dir, channel, &header),
                    Verdict::Terminate
                ) {
                    warn!(
                        %connection_ref,
                        channel = channel.name(),
                        message_type = header.message_type,
                        message_size = header.message_size,
                        "policy header check verdict Terminate; ending relay"
                    );
                    writer.flush().await?;
                    return Ok(());
                }
            }

            let frame_len = MessageHeader::SIZE + header.message_size as usize;
            if available < frame_len {
                break; // header seen, body incomplete — read more
            }

            let frame_start = consumed;
            let payload_start = frame_start + MessageHeader::SIZE;
            let frame_end = frame_start + frame_len;
            let verdict = policy.inspect(dir, channel, &header, &buf[payload_start..frame_end]);

            match verdict {
                Verdict::Forward => {
                    // Forward the exact framed bytes, never re-encoded.
                    writer.write_all(&buf[frame_start..frame_end]).await?;
                    crate::metrics::add_relayed_bytes(dir, frame_len as u64);
                }
                Verdict::Drop => {
                    debug!(
                        %connection_ref,
                        channel = channel.name(),
                        message_type = header.message_type,
                        message_size = header.message_size,
                        "policy verdict Drop; message swallowed"
                    );
                }
                Verdict::Terminate => {
                    warn!(
                        %connection_ref,
                        channel = channel.name(),
                        message_type = header.message_type,
                        "policy verdict Terminate; ending relay"
                    );
                    writer.flush().await?;
                    return Ok(());
                }
            }

            consumed += frame_len;
            // The next message (if any) at the new cursor has not been
            // header-checked yet.
            header_checked = false;
        }

        if consumed > 0 {
            buf.drain(..consumed);
        }
        // Flush the batch of messages forwarded from this read before we block
        // on the next read, so latency does not depend on the next arrival.
        writer.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PermissivePolicy;
    use shakenfist_spice_protocol::messages::make_message;
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// A test reader that hands out one preloaded chunk per `poll_read`, then
    /// signals EOF. This deterministically forces the pump to reassemble
    /// messages that are split across reads (partial header, partial body).
    struct ChunkedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into(),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                // Test chunks are always smaller than the pump's read buffer.
                assert!(chunk.len() <= buf.remaining(), "test chunk exceeds buf");
                buf.put_slice(&chunk);
            }
            // Empty (no chunk written) => 0 bytes read => EOF.
            Poll::Ready(Ok(()))
        }
    }

    /// Test-only policy that drops every message.
    struct DropPolicy;
    impl Policy for DropPolicy {
        fn inspect(
            &mut self,
            _: Direction,
            _: ChannelType,
            _: &MessageHeader,
            _: &[u8],
        ) -> Verdict {
            Verdict::Drop
        }
    }

    /// Test-only policy that terminates on the first message.
    struct TerminatePolicy;
    impl Policy for TerminatePolicy {
        fn inspect(
            &mut self,
            _: Direction,
            _: ChannelType,
            _: &MessageHeader,
            _: &[u8],
        ) -> Verdict {
            Verdict::Terminate
        }
    }

    /// Test-only policy that counts `check_header` calls via a shared counter,
    /// to prove the pump runs the L0 header check EXACTLY once per message even
    /// when the message body is split across several reads (the `header_checked`
    /// dedup invariant that guards the rate counter from double-counting).
    struct CountingCheckPolicy {
        header_checks: Arc<AtomicUsize>,
    }
    impl Policy for CountingCheckPolicy {
        fn check_header(&mut self, _: Direction, _: ChannelType, _: &MessageHeader) -> Verdict {
            self.header_checks.fetch_add(1, Ordering::Relaxed);
            Verdict::Forward
        }
        fn inspect(
            &mut self,
            _: Direction,
            _: ChannelType,
            _: &MessageHeader,
            _: &[u8],
        ) -> Verdict {
            Verdict::Forward
        }
    }

    /// Test-only policy that terminates in the pre-body header check (L0),
    /// exercising the relay's `check_header` wiring. `inspect` would forward,
    /// so a Terminate here proves the header check acted before the body.
    struct HeaderTerminatePolicy;
    impl Policy for HeaderTerminatePolicy {
        fn inspect(
            &mut self,
            _: Direction,
            _: ChannelType,
            _: &MessageHeader,
            _: &[u8],
        ) -> Verdict {
            Verdict::Forward
        }
        fn check_header(&mut self, _: Direction, _: ChannelType, _: &MessageHeader) -> Verdict {
            Verdict::Terminate
        }
    }

    /// A reader that is always `Pending`: it never yields bytes and never
    /// signals EOF, modelling a silent-but-connected peer.
    struct PendingReader;
    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// Run `pump` from a `ChunkedReader` over `chunks` into an in-memory sink,
    /// returning `(collected_output, pump_result)`.
    async fn run_pump<P>(chunks: Vec<Vec<u8>>, policy: P) -> (Vec<u8>, Result<()>)
    where
        P: Policy + Send + 'static,
    {
        let reader = ChunkedReader::new(chunks);
        let (out_writer, mut out_reader) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            pump(
                reader,
                out_writer,
                policy,
                Direction::ClientToServer,
                ChannelType::Main,
                "test",
            )
            .await
        });

        let mut collected = Vec::new();
        out_reader
            .read_to_end(&mut collected)
            .await
            .expect("reading pump output failed");
        let result = task.await.expect("pump task panicked");
        (collected, result)
    }

    #[tokio::test]
    async fn forward_preserves_bytes_and_order() {
        let msg1 = make_message(101, b"hello");
        let msg2 = make_message(202, b"a longer payload!!");

        let mut expected = Vec::new();
        expected.extend_from_slice(&msg1);
        expected.extend_from_slice(&msg2);

        // Both messages arrive in a single read.
        let (out, result) = run_pump(vec![expected.clone()], PermissivePolicy).await;
        result.expect("pump returned an error");
        assert_eq!(out, expected, "framed bytes must pass through unchanged");
    }

    #[tokio::test]
    async fn forward_reassembles_split_messages() {
        let msg1 = make_message(101, b"hello");
        let msg2 = make_message(202, b"a longer payload!!");

        let mut whole = Vec::new();
        whole.extend_from_slice(&msg1);
        whole.extend_from_slice(&msg2);

        // Split so the first chunk holds only a partial header (3 of 6 bytes),
        // the second finishes the header and part of msg1's body, and the last
        // carries the remainder spanning into msg2.
        let chunks = vec![
            whole[..3].to_vec(),
            whole[3..8].to_vec(),
            whole[8..].to_vec(),
        ];

        let (out, result) = run_pump(chunks, PermissivePolicy).await;
        result.expect("pump returned an error");
        assert_eq!(out, whole, "split messages must reassemble unchanged");
    }

    #[tokio::test]
    async fn check_header_runs_exactly_once_per_message_across_split_reads() {
        // The L0 header check (which drives the rate counter) MUST run exactly
        // once per message. This guards the `header_checked` dedup: a
        // regression that re-ran check_header on every partial read would
        // double-count a body that spans reads. One message, body split so its
        // header completes in the second chunk and its body spans into a third.
        let msg = make_message(101, b"a body that spans several reads");
        let chunks = vec![
            msg[..3].to_vec(),  // partial header (3 of 6 bytes)
            msg[3..9].to_vec(), // finishes the header + a little body
            msg[9..].to_vec(),  // the rest of the body
        ];
        let counter = Arc::new(AtomicUsize::new(0));
        let policy = CountingCheckPolicy {
            header_checks: Arc::clone(&counter),
        };
        let (out, result) = run_pump(chunks, policy).await;
        result.expect("pump returned an error");
        assert_eq!(out, msg, "the message must be forwarded intact");
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "check_header must run exactly once per message even when the body \
             is split across reads"
        );
    }

    #[tokio::test]
    async fn drop_forwards_nothing_but_consumes_input() {
        let msg1 = make_message(1, b"drop me");
        let msg2 = make_message(2, b"me too");
        let mut input = Vec::new();
        input.extend_from_slice(&msg1);
        input.extend_from_slice(&msg2);

        let (out, result) = run_pump(vec![input], DropPolicy).await;
        result.expect("pump returned an error");
        assert!(out.is_empty(), "dropped messages must not be forwarded");
    }

    #[tokio::test]
    async fn terminate_ends_promptly_without_forwarding() {
        let msg1 = make_message(1, b"first");
        let msg2 = make_message(2, b"second");
        let mut input = Vec::new();
        input.extend_from_slice(&msg1);
        input.extend_from_slice(&msg2);

        let (out, result) = run_pump(vec![input], TerminatePolicy).await;
        result.expect("terminate should end the pump with Ok");
        assert!(
            out.is_empty(),
            "the terminating message must not be forwarded"
        );
    }

    #[tokio::test]
    async fn oversized_message_is_rejected() {
        // A header claiming a body far larger than the cap, with no body.
        let header = MessageHeader {
            message_type: 1,
            message_size: MAX_MESSAGE_SIZE + 1,
        };
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("header write failed");

        let (out, result) = run_pump(vec![bytes], PermissivePolicy).await;
        assert!(
            result.is_err(),
            "an oversized frame must return an error, not buffer forever"
        );
        assert!(
            out.is_empty(),
            "nothing should be forwarded for a bad frame"
        );
    }

    #[tokio::test]
    async fn header_check_terminate_ends_without_forwarding() {
        // The header check must fire before the body is forwarded, so nothing
        // reaches the writer even though `inspect` would have forwarded.
        let msg1 = make_message(101, b"hello");
        let msg2 = make_message(202, b"world");
        let mut input = Vec::new();
        input.extend_from_slice(&msg1);
        input.extend_from_slice(&msg2);

        let (out, result) = run_pump(vec![input], HeaderTerminatePolicy).await;
        result.expect("header-check terminate should end the pump with Ok");
        assert!(
            out.is_empty(),
            "a header-check Terminate must forward nothing"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_read_timeout_ends_pump_cleanly() {
        // With the clock paused, tokio auto-advances to the idle-timeout
        // deadline once the (forever-Pending) reader leaves the task idle, so
        // this is deterministic and does not wait 15 real minutes.
        let (out_writer, _out_reader) = tokio::io::duplex(64 * 1024);
        let result = pump(
            PendingReader,
            out_writer,
            PermissivePolicy,
            Direction::ClientToServer,
            ChannelType::Main,
            "test",
        )
        .await;
        result.expect("idle-read timeout must end the pump cleanly with Ok");
    }
}
