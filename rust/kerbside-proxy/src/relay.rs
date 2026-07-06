//! The inspection-first SPICE relay.
//!
//! This relays an authorized client `SpiceStream` to the connected backend
//! (hypervisor) `SpiceStream`, framing each direction by the 6-byte SPICE
//! mini-header (`MessageHeader`). Every complete message is passed through a
//! [`Policy`] before it is forwarded, so this is deliberately NOT an opaque
//! `copy_bidirectional`: it is the seam phase 4 fills with L0/L1 firewall
//! enforcement (master-plan design decision 5). Phase 3 ships
//! [`PermissivePolicy`], which forwards everything unchanged.
//!
//! One accepted client connection = one backend channel connection = one
//! relayed SPICE channel (SPICE opens a TCP connection per channel).

use anyhow::{anyhow, Result};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::messages::MessageHeader;
use shakenfist_spice_protocol::ChannelType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::policy::{Direction, PermissivePolicy, Policy, Verdict};

/// Sanity cap on a single framed SPICE message's declared body size.
///
/// A light L0-ish safety even before phase 4: a peer that claims an absurd
/// `message_size` must not make us buffer gigabytes waiting for a body that
/// will never arrive. 16 MiB is generous for any legitimate SPICE message
/// (the largest are image/surface payloads). PLACEHOLDER: phase 4 tightens
/// this per channel/direction as part of L0 enforcement.
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// How much we read from the socket per `read` call. The reassembly buffer
/// grows as needed for a single large message; this only bounds one read.
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// Relay the authorized client connection to the connected backend channel.
///
/// Splits both streams into read/write halves and runs two framing pumps
/// concurrently (client->server and server->client), each with its own
/// [`PermissivePolicy`] instance. A SPICE channel is a single duplex TCP
/// connection: once EITHER direction ends (EOF, an I/O error, or a policy
/// `Terminate`), the whole session is over, so we `select!` and let the first
/// pump to finish tear the other down (dropping its future).
///
/// Phase 4 swaps `PermissivePolicy` here for the enforcing policy type; the
/// `run` signature is unchanged.
///
/// Returns `Ok(())` on normal teardown. Genuine faults (a protocol violation
/// such as an oversized frame, or an I/O error) are logged here; we still
/// return `Ok(())` because the caller deregisters the channel and closes the
/// client either way, and a torn-down socket is not separately actionable.
/// Bytes forwarded on each `Verdict::Forward` are counted via
/// `metrics::add_relayed_bytes`; a dedicated fault-count metric is not part
/// of this step and is left for phase 4, which is where faults gain
/// interesting structure (which policy rule tripped, on which channel).
pub async fn run(
    client: SpiceStream,
    backend: SpiceStream,
    channel_type: ChannelType,
    connection_ref: &str,
) -> Result<()> {
    info!(
        %connection_ref,
        channel_type = channel_type.name(),
        "relay starting"
    );

    let (client_reader, client_writer) = tokio::io::split(client);
    let (backend_reader, backend_writer) = tokio::io::split(backend);

    // Each direction gets its OWN policy instance. PermissivePolicy is
    // stateless, so this needs no lock; see policy.rs for the phase-4
    // shared-state note.
    let client_to_server = pump(
        client_reader,
        backend_writer,
        PermissivePolicy,
        Direction::ClientToServer,
        channel_type,
        connection_ref,
    );
    let server_to_client = pump(
        backend_reader,
        client_writer,
        PermissivePolicy,
        Direction::ServerToClient,
        channel_type,
        connection_ref,
    );

    let result = tokio::select! {
        r = client_to_server => r,
        r = server_to_client => r,
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

    // Normal teardown is uniform from the caller's perspective; do not
    // propagate the error (see the doc comment above).
    Ok(())
}

/// The framing pump for one direction.
///
/// Generic over the reader/writer/policy so it is unit-testable with
/// `tokio::io::duplex` and in-memory readers (a `SpiceStream` cannot wrap a
/// duplex). Reads bytes into a reassembly buffer, and for every complete
/// framed message (`MessageHeader` + `message_size` body) present, consults
/// `policy` and acts on its [`Verdict`]:
///
/// - [`Verdict::Forward`]: write the ORIGINAL framed bytes (header + body,
///   unchanged — never re-encoded) to `writer`, then advance past them.
/// - [`Verdict::Drop`]: advance past the message without forwarding it.
/// - [`Verdict::Terminate`]: flush and end the pump (which ends the relay).
///
/// Returns `Ok(())` on clean EOF, or `Err` on a protocol violation (an
/// oversized frame) or an underlying I/O error.
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

    loop {
        let n = reader.read(&mut chunk).await?;
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
    use shakenfist_spice_protocol::messages::make_message;
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
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
}
