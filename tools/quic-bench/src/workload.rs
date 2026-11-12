//! The workload, written once and run over either transport.
//!
//! A session is `--channels` byte-duplex channels. One saturates with bulk
//! writes from the server towards the client, which is the direction a SPICE
//! display channel loads; one carries small request/response exchanges the
//! client times, which is the shape of an input echo; the rest are opened and
//! then quiet, which is what a real session's cursor, playback and record
//! channels do most of the time.
//!
//! Everything here is generic over `AsyncRead + AsyncWrite`, so a TCP
//! connection and a QUIC bidirectional stream run byte-for-byte the same
//! exchange and the only difference between the two arms is the transport.

use std::io;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bulk sink: the server writes until the peer goes away.
pub const ROLE_BULK: u8 = 0;
/// Timed request/response: the server echoes each request verbatim.
pub const ROLE_INTERACTIVE: u8 = 1;
/// Open but quiet: one exchange to make the channel real, then nothing.
pub const ROLE_IDLE: u8 = 2;

/// Role byte plus a little-endian u32 payload size.
const HEADER_LEN: usize = 5;

/// How long to keep waiting for any one interactive response. A response still
/// outstanding after this is recorded as a censored sample at the bound and
/// counted as a timeout, rather than silently dropping it.
///
/// The bound is per request, not per run. Anchored to the end of the
/// measurement window instead, a request stalled early in a run would wait out
/// the whole remainder before being counted, which costs the repeat most of
/// its samples and -- because the stalled exchange itself is never
/// recorded -- makes a catastrophic stall look like a quiet repeat rather than
/// a tail.
const RESPONSE_GRACE: Duration = Duration::from_secs(3);

/// The role the channel at a given index plays.
pub fn role_for(index: usize) -> u8 {
    match index {
        0 => ROLE_BULK,
        1 => ROLE_INTERACTIVE,
        _ => ROLE_IDLE,
    }
}

/// Timings and sizes shared by both arms.
#[derive(Clone, Copy, Debug)]
pub struct Workload {
    /// Total length of the measurement window, warmup included.
    pub duration: Duration,
    /// Samples and bytes inside this much of the window are discarded, so the
    /// figures describe a congestion controller that has finished ramping.
    pub warmup: Duration,
    /// Gap between an interactive response and the next request.
    pub interval: Duration,
    /// Size of each interactive request, and so of its echo.
    pub request_bytes: usize,
    /// Size of each bulk write the server makes.
    pub bulk_chunk: usize,
}

/// One timed request/response exchange.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// Milliseconds from the start of the measurement window to the request.
    pub offset_ms: f64,
    /// Round trip, request written to echo fully read.
    pub rtt_us: u64,
}

/// What the interactive channel saw.
#[derive(Debug, Default)]
pub struct Interactive {
    pub samples: Vec<Sample>,
    /// Requests whose echo never arrived inside the grace period.
    pub timeouts: u64,
}

/// What the saturating channel saw.
#[derive(Debug, Default)]
pub struct Bulk {
    /// Every byte read, warmup included.
    pub bytes_total: u64,
    /// Bytes read after the warmup window closed.
    pub bytes_steady: u64,
    /// Wall time the steady bytes were read over.
    pub steady_secs: f64,
}

impl Bulk {
    /// Steady-state throughput in megabits per second, or zero if the steady
    /// window never opened.
    pub fn mbit_per_sec(&self) -> f64 {
        if self.steady_secs <= 0.0 {
            return 0.0;
        }
        (self.bytes_steady as f64 * 8.0) / self.steady_secs / 1_000_000.0
    }
}

fn header(role: u8, size: usize) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0] = role;
    buf[1..].copy_from_slice(&(size as u32).to_le_bytes());
    buf
}

/// Read a channel's header: the role it plays and its payload size.
pub async fn read_header<S>(stream: &mut S) -> io::Result<(u8, usize)>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; HEADER_LEN];
    stream.read_exact(&mut head).await?;
    let size = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if size == 0 || size > 8 * 1024 * 1024 {
        return Err(io::Error::other(format!("implausible payload size {size}")));
    }
    Ok((head[0], size))
}

/// Server side of one channel whose header has already been read. Returns when
/// the peer closes the channel, which is how a run ends.
///
/// Split from the header read so the QUIC server can look at the role before
/// it hands the stream over -- it needs the send half, and the role, to set a
/// stream priority.
pub async fn serve_role<S>(mut stream: S, role: u8, size: usize) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match role {
        ROLE_BULK => {
            let chunk = vec![0xa5u8; size];
            loop {
                stream.write_all(&chunk).await?;
            }
        }
        ROLE_INTERACTIVE | ROLE_IDLE => {
            let mut buf = vec![0u8; size];
            loop {
                stream.read_exact(&mut buf).await?;
                stream.write_all(&buf).await?;
                stream.flush().await?;
            }
        }
        other => Err(io::Error::other(format!("unknown channel role {other}"))),
    }
}

/// Server side of one channel, header and all.
pub async fn serve_channel<S>(mut stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (role, size) = read_header(&mut stream).await?;
    serve_role(stream, role, size).await
}

/// Client side of the saturating channel: ask the server to flood, then read
/// and count until the window closes.
pub async fn run_bulk<S>(mut stream: S, work: &Workload, start: Instant) -> io::Result<Bulk>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&header(ROLE_BULK, work.bulk_chunk))
        .await?;
    stream.flush().await?;

    let deadline = start + work.duration;
    let steady_from = start + work.warmup;
    let mut buf = vec![0u8; 256 * 1024];
    let mut result = Bulk::default();
    let mut steady_begin: Option<Instant> = None;
    let mut steady_end = steady_from;

    loop {
        let read = tokio::time::timeout_at(deadline.into(), stream.read(&mut buf)).await;
        let Ok(read) = read else { break };
        let n = match read {
            Ok(0) => break,
            Ok(n) => n,
            // A reset at the end of the window is the peer tearing down, not a
            // measurement failure: keep what was counted.
            Err(_) => break,
        };
        result.bytes_total += n as u64;
        let now = Instant::now();
        if now >= steady_from {
            if steady_begin.is_none() {
                // Start the steady clock here rather than at steady_from, so
                // the first post-warmup read is not credited with bytes that
                // arrived during the warmup.
                steady_begin = Some(now);
            } else {
                result.bytes_steady += n as u64;
            }
            steady_end = now;
        }
    }

    if let Some(begin) = steady_begin {
        result.steady_secs = steady_end.saturating_duration_since(begin).as_secs_f64();
    }
    Ok(result)
}

/// Client side of the interactive channel: one request outstanding at a time,
/// each round trip recorded. One outstanding request is what makes a lost
/// packet show up as a long round trip rather than hiding behind a later one.
pub async fn run_interactive<S>(
    mut stream: S,
    work: &Workload,
    start: Instant,
) -> io::Result<Interactive>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&header(ROLE_INTERACTIVE, work.request_bytes))
        .await?;
    stream.flush().await?;

    let deadline = start + work.duration;
    let mut request = vec![0x3cu8; work.request_bytes];
    let mut response = vec![0u8; work.request_bytes];
    let mut result = Interactive::default();
    let mut seq: u64 = 0;

    while Instant::now() < deadline {
        request[..8].copy_from_slice(&seq.to_le_bytes());
        let sent_at = Instant::now();
        stream.write_all(&request).await?;
        stream.flush().await?;

        // Whichever comes first: this request's own grace period, or the
        // window's end plus one grace period for a request issued at the death.
        let give_up = (sent_at + RESPONSE_GRACE).min(deadline + RESPONSE_GRACE);
        let echo = tokio::time::timeout_at(give_up.into(), stream.read_exact(&mut response)).await;
        match echo {
            Err(_) => {
                // Censored at the bound: the true round trip is at least this
                // long and unbounded above. Recording it keeps the stall in
                // the distribution, and `timeouts` says how many samples are
                // floors rather than measurements. The byte stream is now
                // desynchronised -- a late echo would fail the sequence check
                // below -- so this channel stops here.
                result.timeouts += 1;
                result.samples.push(Sample {
                    offset_ms: sent_at.saturating_duration_since(start).as_secs_f64() * 1000.0,
                    rtt_us: RESPONSE_GRACE.as_micros() as u64,
                });
                break;
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e),
            Ok(Ok(_)) => {}
        }
        let rtt = sent_at.elapsed();
        if response[..8] != request[..8] {
            return Err(io::Error::other("echo out of sequence"));
        }
        result.samples.push(Sample {
            offset_ms: sent_at.saturating_duration_since(start).as_secs_f64() * 1000.0,
            rtt_us: rtt.as_micros() as u64,
        });
        seq += 1;
        tokio::time::sleep(work.interval).await;
    }

    Ok(result)
}

/// Client side of a quiet channel: one exchange so the server sees it, then
/// hold it open for the rest of the window.
pub async fn run_idle<S>(mut stream: S, work: &Workload, start: Instant) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&header(ROLE_IDLE, 1)).await?;
    stream.write_all(&[0x7eu8]).await?;
    stream.flush().await?;
    let mut echo = [0u8; 1];
    let _ =
        tokio::time::timeout_at((start + work.duration).into(), stream.read_exact(&mut echo)).await;
    tokio::time::sleep_until((start + work.duration).into()).await;
    Ok(())
}
