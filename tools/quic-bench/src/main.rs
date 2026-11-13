//! A transport-only bench for the proxy's client leg.
//!
//! The question it answers: for a session's worth of channels over a lossy,
//! delayed, rate-limited link, does one QUIC connection with a stream per
//! channel give a better or worse interactive round trip than the independent
//! TCP connection per channel the proxy uses today, and what does each arm get
//! through while it does?
//!
//! There is no SPICE here, no guest and no spice-server: those add far more
//! variance than any transport effect, so the bench carries the traffic shape
//! and nothing else. See docs/performance/quic-transport-bench.md.
//!
//! Run it through run-bench.sh, which builds the shaped link the measurement
//! depends on. Running the binary by hand on an unshaped loopback measures
//! nothing interesting.

mod nogso;
mod quic;
mod tcp;
mod workload;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::{AsyncRead, AsyncWrite};

use workload::{Bulk, Interactive, Workload};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    Tcp,
    Quic,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Quic => f.write_str("quic"),
        }
    }
}

/// Congestion controller for the QUIC arm. The TCP arm takes the one the
/// network namespace's `tcp_congestion_control` names, which the harness sets,
/// so the two arms can be matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Cc {
    Cubic,
    Bbr,
    Reno,
}

impl fmt::Display for Cc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cubic => f.write_str("cubic"),
            Self::Bbr => f.write_str("bbr"),
            Self::Reno => f.write_str("reno"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Compare per-channel TCP with one QUIC connection per session.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve channels until killed.
    Server {
        #[arg(long, value_enum)]
        transport: Transport,
        #[arg(long)]
        listen: SocketAddr,
        /// Server certificate chain, PEM. QUIC only.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Server private key, PEM. QUIC only.
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Cc::Cubic)]
        cc: Cc,
        #[arg(long, default_value_t = 5)]
        channels: u32,
        /// Leave quinn's segmentation offload enabled. The positive control
        /// for the queue-accounting check, and nothing else: a run made with
        /// this measures a link that does not exist.
        #[arg(long)]
        allow_gso: bool,
        /// Give the interactive stream a send priority above the saturating
        /// one. A labelled sensitivity arm, not the headline: the headline
        /// leaves every stream at the default priority, which is what a
        /// straightforward integration would do.
        #[arg(long)]
        priority_interactive: bool,
    },
    /// Run one measurement and write its results as JSON.
    Client {
        #[arg(long, value_enum)]
        transport: Transport,
        #[arg(long)]
        connect: SocketAddr,
        /// Server certificate, PEM, used as the only trust root. QUIC only.
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Cc::Cubic)]
        cc: Cc,
        #[arg(long, default_value_t = 5)]
        channels: u32,
        #[arg(long, default_value_t = 40)]
        duration_secs: u64,
        #[arg(long, default_value_t = 5)]
        warmup_secs: u64,
        /// Gap between one interactive response and the next request.
        #[arg(long, default_value_t = 20)]
        interval_ms: u64,
        #[arg(long, default_value_t = 64)]
        request_bytes: usize,
        #[arg(long, default_value_t = 65536)]
        bulk_chunk: usize,
        /// Free-form label carried through to the results, e.g. the cell name.
        #[arg(long, default_value = "")]
        label: String,
        /// Where to write the results JSON. Defaults to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Leave quinn's segmentation offload enabled. See the server's flag.
        #[arg(long)]
        allow_gso: bool,
        /// Give the interactive stream a send priority. See the server's flag.
        #[arg(long)]
        priority_interactive: bool,
    },
}

fn install_crypto_provider() {
    // Explicit rather than implicit: quinn's rustls-ring feature makes ring
    // available, but the process default has to be installed before any
    // rustls config is built.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("a crypto provider was already installed");
    }
}

/// Nearest-rank percentile over a sorted slice.
///
/// `None` for an empty slice rather than zero: a run that produced no
/// steady-state samples has no percentile, and writing 0 would put a
/// plausible-looking number in the results for a cell that failed.
fn percentile(sorted: &[u64], quantile: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

/// Drive every channel for the measurement window and return what the two
/// interesting ones saw.
async fn run_channels<S>(streams: Vec<S>, work: Workload) -> Result<(Interactive, Bulk), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let start = Instant::now();
    let mut bulk = None;
    let mut interactive = None;
    let mut idle = Vec::new();

    for (index, stream) in streams.into_iter().enumerate() {
        match workload::role_for(index) {
            workload::ROLE_BULK => {
                bulk = Some(tokio::spawn(async move {
                    workload::run_bulk(stream, &work, start).await
                }));
            }
            workload::ROLE_INTERACTIVE => {
                interactive = Some(tokio::spawn(async move {
                    workload::run_interactive(stream, &work, start).await
                }));
            }
            _ => {
                idle.push(tokio::spawn(async move {
                    workload::run_idle(stream, &work, start).await
                }));
            }
        }
    }

    let bulk = bulk.ok_or("no saturating channel: --channels must be at least 1")?;
    let interactive = interactive.ok_or("no interactive channel: --channels must be at least 2")?;
    let interactive = interactive.await??;
    let bulk = bulk.await??;
    for task in idle {
        let _ = task.await;
    }
    Ok((interactive, bulk))
}

#[allow(clippy::too_many_arguments)]
fn results_json(
    label: &str,
    transport: Transport,
    cc: Cc,
    channels: u32,
    work: &Workload,
    connect_ms: f64,
    gso: Option<(usize, usize)>,
    interactive: &Interactive,
    bulk: &Bulk,
) -> serde_json::Value {
    let warmup_ms = work.warmup.as_secs_f64() * 1000.0;
    let mut steady: Vec<u64> = interactive
        .samples
        .iter()
        .filter(|s| s.offset_ms >= warmup_ms)
        .map(|s| s.rtt_us)
        .collect();
    steady.sort_unstable();

    serde_json::json!({
        "label": label,
        "transport": transport.to_string(),
        "quic_cc": if transport == Transport::Quic { Some(cc.to_string()) } else { None },
        "channels": channels,
        "duration_secs": work.duration.as_secs(),
        "warmup_secs": work.warmup.as_secs(),
        "interval_ms": work.interval.as_millis(),
        "request_bytes": work.request_bytes,
        "bulk_chunk": work.bulk_chunk,
        "connect_ms": connect_ms,
        "gso": gso.map(|(available, used)| serde_json::json!({
            "segments_available": available,
            "segments_used": used,
            "pinned_mtu": quic::PINNED_MTU,
        })),
        "interactive": {
            "samples_total": interactive.samples.len(),
            "samples_steady": steady.len(),
            "timeouts": interactive.timeouts,
            "p50_us": percentile(&steady, 0.50),
            "p95_us": percentile(&steady, 0.95),
            "p99_us": percentile(&steady, 0.99),
            "min_us": steady.first().copied(),
            "max_us": steady.last().copied(),
            "raw": interactive.samples.iter().map(|s| serde_json::json!([s.offset_ms, s.rtt_us])).collect::<Vec<_>>(),
        },
        "bulk": {
            "bytes_total": bulk.bytes_total,
            "bytes_steady": bulk.bytes_steady,
            "steady_secs": bulk.steady_secs,
            "mbit_per_sec": bulk.mbit_per_sec(),
        },
    })
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server {
            transport,
            listen,
            cert,
            key,
            cc,
            channels,
            allow_gso,
            priority_interactive,
        } => match transport {
            Transport::Tcp => tcp::serve(listen).await,
            Transport::Quic => {
                install_crypto_provider();
                let cert = cert.ok_or("--cert is required for the quic server")?;
                let key = key.ok_or("--key is required for the quic server")?;
                quic::serve(
                    listen,
                    &cert,
                    &key,
                    cc,
                    channels,
                    allow_gso,
                    priority_interactive,
                )
                .await
            }
        },
        Command::Client {
            transport,
            connect,
            cert,
            cc,
            channels,
            duration_secs,
            warmup_secs,
            interval_ms,
            request_bytes,
            bulk_chunk,
            label,
            out,
            allow_gso,
            priority_interactive,
        } => {
            if request_bytes < 8 {
                return Err(
                    "--request-bytes must be at least 8, to carry the sequence number".into(),
                );
            }
            if warmup_secs >= duration_secs {
                return Err("--warmup-secs must be shorter than --duration-secs".into());
            }
            let work = Workload {
                duration: Duration::from_secs(duration_secs),
                warmup: Duration::from_secs(warmup_secs),
                interval: Duration::from_millis(interval_ms),
                request_bytes,
                bulk_chunk,
            };

            let (connect_ms, gso, interactive, bulk) = match transport {
                Transport::Tcp => {
                    let (streams, connect_ms) = tcp::connect(connect, channels).await?;
                    let (interactive, bulk) = run_channels(streams, work).await?;
                    (connect_ms, None, interactive, bulk)
                }
                Transport::Quic => {
                    install_crypto_provider();
                    let cert = cert.ok_or("--cert is required for the quic client")?;
                    let (endpoint, connection, facts) =
                        quic::connect(connect, &cert, cc, channels, allow_gso).await?;
                    let streams =
                        quic::open_channels(&connection, channels, priority_interactive).await?;
                    let (interactive, bulk) = run_channels(streams, work).await?;
                    connection.close(0u32.into(), b"done");
                    endpoint.wait_idle().await;
                    (
                        facts.connect_ms,
                        Some((facts.gso_segments_available, facts.gso_segments_used)),
                        interactive,
                        bulk,
                    )
                }
            };

            let json = results_json(
                &label,
                transport,
                cc,
                channels,
                &work,
                connect_ms,
                gso,
                &interactive,
                &bulk,
            );
            let rendered = serde_json::to_string(&json)?;
            match out {
                Some(path) => std::fs::write(path, rendered)?,
                None => println!("{rendered}"),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::path::Path;
    use std::process;

    use crate::workload::{Bulk, Interactive, Sample, ROLE_BULK, ROLE_IDLE, ROLE_INTERACTIVE};

    #[test]
    fn percentile_of_nothing_is_none() {
        assert_eq!(percentile(&[], 0.95), None);
    }

    #[test]
    fn percentile_is_nearest_rank() {
        // Ten samples, so 0.95 and 0.99 land between ranks and rounding up
        // is distinguishable from rounding down: 0.95 * 10 = 9.5 takes the
        // tenth sample, not the ninth.
        let sorted: Vec<u64> = (1..=10).collect();
        assert_eq!(percentile(&sorted, 0.50), Some(5));
        assert_eq!(percentile(&sorted, 0.95), Some(10));
        assert_eq!(percentile(&sorted, 0.99), Some(10));
        assert_eq!(percentile(&sorted, 0.90), Some(9));

        // And on a length where the ranks are exact, the same values.
        let hundred: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&hundred, 0.50), Some(50));
        assert_eq!(percentile(&hundred, 0.95), Some(95));
        assert_eq!(percentile(&hundred, 0.99), Some(99));
    }

    #[test]
    fn percentile_never_runs_off_the_bottom() {
        // A quantile of 0 gives a rank of 0, which would index -1 and
        // underflow without the clamp's lower bound. Its upper bound is
        // unreachable for a quantile of 1.0 or less, and the caller only ever
        // passes 0.50, 0.95 and 0.99.
        assert_eq!(percentile(&[7], 0.0), Some(7));
        assert_eq!(percentile(&[7], 1.0), Some(7));
        assert_eq!(percentile(&[1, 2, 3], 0.0), Some(1));
        assert_eq!(percentile(&[1, 2, 3], 1.0), Some(3));
    }

    #[test]
    fn throughput_without_a_steady_window_is_zero_not_a_division_by_zero() {
        let bulk = Bulk::default();
        assert_eq!(bulk.steady_secs, 0.0);
        assert_eq!(bulk.mbit_per_sec(), 0.0);
    }

    #[test]
    fn throughput_is_megabits_of_the_steady_bytes_only() {
        let bulk = Bulk {
            bytes_total: 2_000_000,
            bytes_steady: 1_250_000,
            steady_secs: 10.0,
        };
        // 1.25 MB over 10 s is 1 Mbit/s, and the warmup bytes do not count.
        assert!((bulk.mbit_per_sec() - 1.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn a_header_round_trips_its_role_and_size() {
        // Role byte, then the size little-endian: role 1, 64 bytes.
        let bytes: &[u8] = &[ROLE_INTERACTIVE, 64, 0, 0, 0];
        let mut reader = bytes;
        let (role, size) = workload::read_header(&mut reader).await.unwrap();
        assert_eq!(role, ROLE_INTERACTIVE);
        assert_eq!(size, 64);
    }

    #[tokio::test]
    async fn a_header_claiming_an_implausible_size_is_refused() {
        // Zero, and anything above the 8 MiB ceiling, are both rejected
        // rather than used to size an allocation.
        let zero: &[u8] = &[ROLE_BULK, 0, 0, 0, 0];
        let mut reader = zero;
        assert!(workload::read_header(&mut reader).await.is_err());

        let huge: &[u8] = &[ROLE_BULK, 1, 0, 0, 1];
        let mut reader = huge;
        assert!(workload::read_header(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn a_truncated_header_is_an_error_not_a_default() {
        let short: &[u8] = &[ROLE_BULK, 64];
        let mut reader = short;
        assert!(workload::read_header(&mut reader).await.is_err());
    }

    #[test]
    fn the_first_two_channels_are_the_measured_ones() {
        assert_eq!(workload::role_for(0), ROLE_BULK);
        assert_eq!(workload::role_for(1), ROLE_INTERACTIVE);
        for index in 2..8 {
            assert_eq!(workload::role_for(index), ROLE_IDLE);
        }
    }

    fn work_with_warmup(duration_secs: u64, warmup_secs: u64) -> Workload {
        Workload {
            duration: Duration::from_secs(duration_secs),
            warmup: Duration::from_secs(warmup_secs),
            interval: Duration::from_millis(20),
            request_bytes: 64,
            bulk_chunk: 65536,
        }
    }

    /// Interactive samples from `(offset_ms, rtt_us)` pairs, in arrival order.
    fn samples(pairs: &[(f64, u64)]) -> Interactive {
        Interactive {
            samples: pairs
                .iter()
                .map(|&(offset_ms, rtt_us)| Sample { offset_ms, rtt_us })
                .collect(),
            timeouts: 0,
        }
    }

    fn published(work: &Workload, interactive: &Interactive) -> serde_json::Value {
        results_json(
            "cell",
            Transport::Quic,
            Cc::Cubic,
            5,
            work,
            1.0,
            Some((64, 1)),
            interactive,
            &Bulk::default(),
        )
    }

    #[test]
    fn only_samples_at_or_after_the_warmup_boundary_are_measured() {
        // The boundary is inclusive at the steady end, so with a five second
        // warmup the sample at exactly 5000 ms is the first measured one and
        // the one a millisecond earlier is the last discarded one. The two
        // discarded samples are given round trips far above every measured
        // one, so admitting either moves the percentiles as well as the count.
        let work = work_with_warmup(10, 5);
        let interactive = samples(&[
            (0.0, 900_000),
            (4_999.0, 800_000),
            (5_000.0, 10),
            (6_000.0, 20),
            (7_000.0, 30),
        ]);

        let json = published(&work, &interactive);
        assert_eq!(json["interactive"]["samples_total"], 5);
        assert_eq!(json["interactive"]["samples_steady"], 3);
        assert_eq!(json["interactive"]["min_us"], 10);
        assert_eq!(json["interactive"]["max_us"], 30);
        assert_eq!(json["interactive"]["p50_us"], 20);
        assert_eq!(json["interactive"]["p95_us"], 30);
        assert_eq!(json["interactive"]["p99_us"], 30);

        // Every sample is still carried raw, warmup included, so the discard
        // can be checked after the run rather than taken on trust.
        assert_eq!(json["interactive"]["raw"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn a_run_whose_samples_all_fall_in_the_warmup_publishes_no_percentiles() {
        // Nothing reached the steady window, so there is no percentile to
        // publish. A number here would be indistinguishable from a measured
        // cell to everything downstream.
        let work = work_with_warmup(10, 5);
        let interactive = samples(&[(0.0, 11), (4_999.9, 12)]);

        let json = published(&work, &interactive);
        assert_eq!(json["interactive"]["samples_total"], 2);
        assert_eq!(json["interactive"]["samples_steady"], 0);
        assert!(json["interactive"]["p50_us"].is_null());
        assert!(json["interactive"]["p95_us"].is_null());
        assert!(json["interactive"]["p99_us"].is_null());
        assert!(json["interactive"]["min_us"].is_null());
        assert!(json["interactive"]["max_us"].is_null());
    }

    #[test]
    fn the_published_percentiles_are_over_sorted_samples() {
        // Arrival order is not sorted order: these three steady round trips
        // arrive 30, 10, 20 and every published figure is of 10, 20, 30.
        let work = work_with_warmup(10, 5);
        let interactive = samples(&[(5_000.0, 30), (6_000.0, 10), (7_000.0, 20)]);

        let json = published(&work, &interactive);
        assert_eq!(json["interactive"]["min_us"], 10);
        assert_eq!(json["interactive"]["max_us"], 30);
        assert_eq!(json["interactive"]["p50_us"], 20);
    }

    #[test]
    fn the_results_name_the_congestion_controller_only_for_the_quic_arm() {
        let work = work_with_warmup(10, 5);
        let interactive = samples(&[(6_000.0, 20)]);

        let quic_arm = results_json(
            "cell",
            Transport::Quic,
            Cc::Bbr,
            5,
            &work,
            1.0,
            Some((64, 1)),
            &interactive,
            &Bulk::default(),
        );
        assert_eq!(quic_arm["transport"], "quic");
        assert_eq!(quic_arm["quic_cc"], "bbr");
        assert_eq!(quic_arm["gso"]["segments_available"], 64);
        assert_eq!(quic_arm["gso"]["segments_used"], 1);
        assert_eq!(quic_arm["gso"]["pinned_mtu"], quic::PINNED_MTU);

        // The TCP arm has no QUIC controller and no segmentation count, and
        // the fields are absent rather than carrying the unused default --
        // which would read as a measured controller for an arm that took the
        // namespace's instead.
        let tcp_arm = results_json(
            "cell",
            Transport::Tcp,
            Cc::Bbr,
            5,
            &work,
            1.0,
            None,
            &interactive,
            &Bulk::default(),
        );
        assert_eq!(tcp_arm["transport"], "tcp");
        assert!(tcp_arm["quic_cc"].is_null());
        assert!(tcp_arm["gso"].is_null());
    }

    #[tokio::test]
    async fn an_encoded_header_decodes_to_the_role_and_size_it_carried() {
        // The ceiling itself is a legal size, and the size is little-endian:
        // read big-endian, 8 MiB would decode as 32768 and be accepted.
        let encoded = workload::header(ROLE_IDLE, 8 * 1024 * 1024);
        let mut reader = &encoded[..];
        let (role, size) = workload::read_header(&mut reader).await.unwrap();
        assert_eq!(role, ROLE_IDLE);
        assert_eq!(size, 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn the_tcp_arm_opens_one_connection_per_channel_with_nagle_off() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..3 {
                held.push(listener.accept().await.unwrap().0);
            }
            held.len()
        });

        let (streams, connect_ms) = tcp::connect(addr, 3).await.unwrap();
        assert_eq!(streams.len(), 3);
        for stream in &streams {
            // SPICE sets TCP_NODELAY on its channels; a channel left with
            // Nagle on measures Nagle rather than the transport.
            assert!(stream.nodelay().unwrap());
        }
        assert_eq!(accepted.await.unwrap(), 3);
        assert!(connect_ms >= 0.0);
    }

    #[tokio::test]
    async fn the_no_gso_socket_reports_one_segment_and_delegates_everything_else() {
        use quinn::{AsyncUdpSocket, Runtime, TokioRuntime};

        let bound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inner = TokioRuntime.wrap_udp_socket(bound).unwrap();
        let wrapped = nogso::NoGso::new(inner.clone());

        assert_eq!(wrapped.max_transmit_segments(), 1);
        assert_eq!(wrapped.max_receive_segments(), inner.max_receive_segments());
        assert_eq!(wrapped.may_fragment(), inner.may_fragment());
        assert_eq!(wrapped.local_addr().unwrap(), inner.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_quic_endpoint_sends_one_datagram_per_write_unless_gso_is_allowed() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let (_off, available, used) = quic::endpoint(bind, None, false).unwrap();
        assert_eq!(used, 1, "a measured run must never batch datagrams");

        // The positive control gets the socket's own batching back, whatever
        // the host offers. Where the host offers only one segment the two
        // configurations are indistinguishable, which is why the run records
        // both numbers.
        let (_on, available_on, used_on) = quic::endpoint(bind, None, true).unwrap();
        assert_eq!(used_on, available_on);
        assert_eq!(available_on, available);
        assert!(available >= 1);
    }

    #[test]
    fn a_certificate_file_is_read_whole_and_one_with_no_certificate_is_refused() {
        // rustls_pemfile parses PEM without looking inside the DER, so these
        // stand in for a chain and a key without needing a real one.
        let dir = TempDir::new();
        let chain = dir.file("chain.pem", &format!("{PEM_CERT}{PEM_CERT}"));
        let not_a_cert = dir.file("notacert.pem", PEM_KEY);

        let certs = quic::load_certs(&chain).unwrap();
        // The whole chain, not just the leaf: an intermediate dropped here
        // would be missing from the chain the client is asked to verify.
        assert_eq!(certs.len(), 2);

        // A file with no certificate in it fails here, naming the file,
        // rather than becoming an empty chain that fails at handshake time.
        assert!(quic::load_certs(&not_a_cert).is_err());
        assert!(quic::load_certs(Path::new("/nonexistent/quic-bench-cert")).is_err());
    }

    #[test]
    fn a_key_file_is_read_and_one_with_no_private_key_is_refused() {
        let dir = TempDir::new();
        let key = dir.file("key.pem", PEM_KEY);
        let not_a_key = dir.file("notakey.pem", PEM_CERT);

        assert_eq!(
            quic::load_key(&key).unwrap().secret_der().to_vec(),
            vec![1u8, 2, 3]
        );
        // Not an empty key: the server would otherwise start with a key
        // nothing can complete a handshake with.
        assert!(quic::load_key(&not_a_key).is_err());
    }

    const PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const PEM_KEY: &str = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n";

    /// A directory of this test's own, holding its fixture files.
    ///
    /// The name is unpredictable -- `RandomState`'s keys are seeded by the
    /// operating system -- and `create_dir` fails rather than follows a
    /// symlink if the path somehow already exists, so a fixture cannot be
    /// written through something another user left waiting on a shared /tmp.
    /// Removal is the guard's `Drop`, so a failed assertion part way through a
    /// test does not leak the directory.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let token = RandomState::new().build_hasher().finish();
            let path =
                std::env::temp_dir().join(format!("quic-bench-{}-{token:016x}", process::id()));
            std::fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
