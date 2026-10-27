//! The transcoding display channel end to end, between a fake backend that
//! emits canned display messages and a fake client that reads what the
//! transcoder sends with ryll's readers and decoders.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use shakenfist_spice_protocol::constants::{capabilities, image_compression};
use shakenfist_spice_protocol::link::SpiceStream;
use shakenfist_spice_protocol::messages::{
    make_message, DisplayInit, DisplayMonitorsConfig, DrawCopy, PreferredCompression,
    ReceiveBuffer, ReceivedMessage, SetAck, SurfaceCreate, WireType,
};
use shakenfist_spice_protocol::{display_client, display_server, ChannelType, ImageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::geometry::{Rectangle, Size};
use super::updates::test_support::{started, Client, Desktop, LZ4};
use super::updates::{Draw, Encoding, UpdateEncoder};
use super::*;
use crate::policy::FirewallPolicy;
use crate::rpc::KerbsideRpc;
use crate::session::{SessionRegistry, SharedState};

/// A bound on every test, so a hang fails rather than stalls.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 4 x 3 tiles, the last column and row partial.
const SIZE: Size = Size {
    width: 228,
    height: 136,
};

/// A connected loopback pair: (accepted side, dialled side).
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dial = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (accepted, _) = listener.accept().await.unwrap();
    (accepted, dial.await.unwrap())
}

/// Shared state whose control service is never reached: no test here
/// records a firewall verdict, so no audit event is sent.
fn state(options: Option<Options>) -> SharedState {
    SharedState {
        rpc: KerbsideRpc::connect(Path::new("/nonexistent/kerbside-transcode-test.sock")),
        node_name: "test-node".to_string(),
        sessions: Arc::new(SessionRegistry::default()),
        backend_rcvbuf_bytes: 0,
        transcode: options.map(Arc::new),
    }
}

fn options(pacing: PacingMode) -> Options {
    Options {
        jpeg_quality: JpegQuality::new(85),
        lossless_delay: Duration::from_millis(500),
        notsent_lowat: 65536,
        pacing,
    }
}

/// A client advertising LZ4 and MONITORS_CONFIG, as spice-gtk does.
fn client_caps() -> ClientCaps {
    ClientCaps {
        common: vec![
            capabilities::AUTH_SELECTION | capabilities::AUTH_SPICE | capabilities::MINI_HEADER,
        ],
        channel: vec![
            capabilities::DISPLAY_LZ4_COMPRESSION | capabilities::DISPLAY_MONITORS_CONFIG,
        ],
    }
}

/// Read the next whole message from `stream`.
async fn next_message(
    stream: &mut TcpStream,
    buffer: &mut ReceiveBuffer,
) -> Option<ReceivedMessage> {
    loop {
        if let Some(message) = buffer.take_message(64 * 1024 * 1024).unwrap() {
            return Some(message);
        }
        let mut chunk = vec![0; 64 * 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

/// A `SURFACE_CREATE` for the primary surface of `size`.
fn surface_create(size: Size) -> Vec<u8> {
    message(
        display_server::SURFACE_CREATE,
        &SurfaceCreate {
            surface_id: 0,
            width: size.width,
            height: size.height,
            format: shakenfist_spice_protocol::constants::surface_fmt::FMT_32_XRGB,
            flags: SURFACE_FLAGS_PRIMARY,
        },
    )
}

/// The fake backend: check the renderer's start-up messages, then send the
/// primary surface and `desktop` drawn on it in LZ4 (and, if `rop3`, a draw
/// the renderer cannot draw), then, once `go` fires, the tiles `changed`
/// differs in. It holds the channel open until the test ends.
async fn fake_backend(
    mut stream: TcpStream,
    desktop: Desktop,
    changed: Desktop,
    rop3: bool,
    go: oneshot::Receiver<()>,
) {
    let mut buffer = ReceiveBuffer::new();
    // The renderer sends INIT, then asks for LZ4, then its codec order.
    let init = next_message(&mut stream, &mut buffer).await.unwrap();
    assert_eq!(init.header.message_type, display_client::INIT);
    DisplayInit::decode(init.payload()).expect("the renderer's INIT parses");
    let preferred = next_message(&mut stream, &mut buffer).await.unwrap();
    assert_eq!(
        preferred.header.message_type,
        display_client::PREFERRED_COMPRESSION
    );
    assert_eq!(
        PreferredCompression::decode(preferred.payload())
            .unwrap()
            .image_compression,
        image_compression::LZ4,
        "the backend is asked for LZ4"
    );

    let mut out = surface_create(desktop.size);
    let (mut encoder, _) = started(&desktop);
    let mut first = UpdateEncoder::new();
    for draw in first.update(&desktop.capture_all(), LZ4).unwrap().draws {
        out.extend(make_message(display_server::DRAW_COPY, &draw.body));
    }
    if rop3 {
        // A draw the renderer cannot draw: counted, and otherwise ignored.
        out.extend(make_message(display_server::DRAW_ROP3, &[0; 40]));
    }
    out.extend(make_message(display_server::MARK, &[]));
    stream.write_all(&out).await.unwrap();

    // The client has seen the first picture before it changes.
    if go.await.is_err() {
        return;
    }
    let mut out = Vec::new();
    for draw in encoder.update(&changed.capture_all(), LZ4).unwrap().draws {
        out.extend(make_message(display_server::DRAW_COPY, &draw.body));
    }
    out.extend(make_message(display_server::MARK, &[]));
    stream.write_all(&out).await.unwrap();

    // Hold the channel open until the test is done with it.
    let mut sink = Vec::new();
    let _ = stream.read_to_end(&mut sink).await;
}

/// A `DRAW_COPY` body the transcoder sent, as the pipeline's `Draw`, so that
/// the shared test client can check and apply it.
fn draw_of(body: &[u8]) -> Draw {
    let decoded = DrawCopy::decode(body).expect("a DRAW_COPY that ryll's reader parses");
    let bbox = decoded.base.bbox;
    let image = decoded.src_bitmap.expect("the draw has an image");
    let encoding = match ImageType::from_u8(image.descriptor.image_type) {
        Some(ImageType::Lz4) => Encoding::Lz4,
        Some(ImageType::Jpeg) => Encoding::Jpeg,
        Some(ImageType::Pixmap) => Encoding::Bitmap,
        other => panic!("unexpected image type {other:?}"),
    };
    Draw {
        rect: Rectangle::new(
            bbox.left as u32,
            bbox.top as u32,
            (bbox.right - bbox.left) as u32,
            (bbox.bottom - bbox.top) as u32,
        ),
        encoding,
        body: body.to_vec(),
    }
}

/// What the fake client has seen.
#[derive(Default)]
struct Seen {
    surface_creates: usize,
    monitors_configs: usize,
    marks: usize,
    /// The rectangles of the draws after the first picture was complete.
    later_draws: Vec<Rectangle>,
}

/// Read the transcoder's messages, checking each with ryll's readers and
/// applying its draws to `client`, until `client` shows `want` at a `MARK`.
async fn read_until_shows(
    stream: &mut TcpStream,
    buffer: &mut ReceiveBuffer,
    client: &mut Client,
    want: &Desktop,
    seen: &mut Seen,
    record_draws: bool,
) {
    loop {
        let message = next_message(stream, buffer)
            .await
            .expect("the transcoder closed the client leg early");
        match message.header.message_type {
            display_server::SURFACE_CREATE => {
                let create = SurfaceCreate::decode(message.payload()).unwrap();
                assert_eq!(
                    (create.width, create.height),
                    (want.size.width, want.size.height)
                );
                assert_eq!(create.surface_id, 0);
                assert_eq!(create.flags & SURFACE_FLAGS_PRIMARY, SURFACE_FLAGS_PRIMARY);
                seen.surface_creates += 1;
            }
            display_server::DRAW_COPY => {
                let draw = draw_of(message.payload());
                if record_draws {
                    seen.later_draws.push(draw.rect);
                }
                client.apply(&draw);
            }
            display_server::MONITORS_CONFIG => {
                let config = DisplayMonitorsConfig::decode(message.payload()).unwrap();
                assert_eq!(config.heads.len(), 1);
                assert_eq!(
                    (config.heads[0].width, config.heads[0].height),
                    (want.size.width, want.size.height)
                );
                seen.monitors_configs += 1;
            }
            display_server::MARK => {
                seen.marks += 1;
                if client.worst_difference(want) == 0 {
                    return;
                }
            }
            other => panic!("unexpected display message {other}"),
        }
    }
}

#[tokio::test]
async fn the_client_is_sent_the_backend_s_surface_and_then_only_what_changed() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let desktop = Desktop::pattern(SIZE);
        let mut changed = desktop.clone();
        changed.flip(70, 70);

        let (backend_far, backend_near) = pair().await;
        let (client_far, mut client_near) = pair().await;
        let (go, ready) = oneshot::channel();
        let backend = tokio::spawn(fake_backend(
            backend_far,
            desktop.clone(),
            changed.clone(),
            true,
            ready,
        ));
        let rop3_before = crate::metrics::transcode_unsupported("draw_rop3");

        let state = state(None);
        let options = options(PacingMode::Socket);
        let caps = client_caps();
        let transcoder = async {
            run(
                &state,
                Arc::new(FirewallPolicy::default()),
                SpiceStream::Plain(client_far),
                SpiceStream::Plain(backend_near),
                &caps,
                "test-transcode",
                &pb::Target::default(),
                CancellationToken::new(),
                &options,
            )
            .await
        };

        let client = async {
            let mut init = Vec::new();
            DisplayInit {
                cache_id: 1,
                cache_size: 20 * 1024 * 1024,
                glz_dict_id: 1,
                glz_dict_window: 3 * 1024 * 1024,
            }
            .write(&mut init);
            client_near
                .write_all(&make_message(display_client::INIT, &init))
                .await
                .unwrap();

            let mut buffer = ReceiveBuffer::new();
            let mut client = Client::new(SIZE);
            let mut seen = Seen::default();
            read_until_shows(
                &mut client_near,
                &mut buffer,
                &mut client,
                &desktop,
                &mut seen,
                false,
            )
            .await;
            assert_eq!(seen.surface_creates, 1, "one surface");
            assert_eq!(seen.monitors_configs, 1, "the client has MONITORS_CONFIG");
            go.send(()).unwrap();

            read_until_shows(
                &mut client_near,
                &mut buffer,
                &mut client,
                &changed,
                &mut seen,
                true,
            )
            .await;
            assert_eq!(
                seen.later_draws,
                vec![Rectangle::new(64, 64, 64, 64)],
                "only the changed tile is sent again"
            );
            assert_eq!(seen.surface_creates, 1, "no new surface for a change");
            // Closing the client ends the transcoder.
            drop(client_near);
        };

        let (result, ()) = tokio::join!(transcoder, client);
        result.expect("the transcoder returns Ok however it ends");
        backend.abort();
        assert_eq!(
            crate::metrics::transcode_unsupported("draw_rop3"),
            rop3_before + 1,
            "the ROP3 draw was counted"
        );
    })
    .await
    .expect("the test timed out");
}

#[tokio::test]
async fn ack_pacing_sends_set_ack_and_waits_for_acks() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let desktop = Desktop::pattern(SIZE);
        let (backend_far, backend_near) = pair().await;
        let (client_far, mut client_near) = pair().await;
        let (_go, ready) = oneshot::channel();
        let backend = tokio::spawn(fake_backend(
            backend_far,
            desktop.clone(),
            desktop.clone(),
            false,
            ready,
        ));

        let state = state(None);
        let options = options(PacingMode::AckWindow(1));
        let caps = client_caps();
        let cancel = CancellationToken::new();
        let target = pb::Target::default();
        let transcoder = run(
            &state,
            Arc::new(FirewallPolicy::default()),
            SpiceStream::Plain(client_far),
            SpiceStream::Plain(backend_near),
            &caps,
            "test-transcode-ack",
            &target,
            cancel.clone(),
            &options,
        );

        let client = async {
            let mut buffer = ReceiveBuffer::new();
            let first = next_message(&mut client_near, &mut buffer).await.unwrap();
            assert_eq!(first.header.message_type, display_server::SET_ACK);
            let set_ack = SetAck::decode(first.payload()).unwrap();
            assert_eq!(set_ack.window, 1);

            let mut init = Vec::new();
            DisplayInit {
                cache_id: 1,
                cache_size: 0,
                glz_dict_id: 1,
                glz_dict_window: 0,
            }
            .write(&mut init);
            client_near
                .write_all(&make_message(display_client::INIT, &init))
                .await
                .unwrap();

            // A window of 1 lets 2W + 1 = 3 messages out before an ACK, and
            // SET_ACK was the first of them.
            for _ in 0..2 {
                next_message(&mut client_near, &mut buffer).await.unwrap();
            }
            let stalled = tokio::time::timeout(
                Duration::from_millis(500),
                next_message(&mut client_near, &mut buffer),
            )
            .await;
            assert!(stalled.is_err(), "nothing more is sent before an ACK");

            client_near
                .write_all(&make_message(display_client::ACK, &[]))
                .await
                .unwrap();
            let resumed = tokio::time::timeout(
                Duration::from_secs(5),
                next_message(&mut client_near, &mut buffer),
            )
            .await
            .expect("an ACK lets the transcoder send again");
            assert!(resumed.is_some());
            cancel.cancel();
        };

        let (result, ()) = tokio::join!(transcoder, client);
        result.expect("the transcoder returns Ok however it ends");
        backend.abort();
    })
    .await
    .expect("the test timed out");
}

#[tokio::test]
async fn only_the_first_display_channel_is_transcoded() {
    let off = state(None);
    assert!(choose(&off, ChannelType::Display, 0, "test").is_none());

    let on = state(Some(options(PacingMode::Socket)));
    assert!(choose(&on, ChannelType::Display, 0, "test").is_some());
    assert!(
        choose(&on, ChannelType::Display, 1, "test").is_none(),
        "a second display is relayed"
    );
    assert!(choose(&on, ChannelType::Main, 0, "test").is_none());
    assert!(choose(&on, ChannelType::Cursor, 0, "test").is_none());
}

#[test]
fn the_backend_is_dialled_for_the_renderer_not_the_client() {
    let caps = BACKEND_DISPLAY_CAPS[0];
    // Lossless draws, no streams.
    assert_ne!(caps & capabilities::DISPLAY_LZ4_COMPRESSION, 0);
    assert_ne!(caps & capabilities::DISPLAY_PREF_COMPRESSION, 0);
    assert_ne!(caps & capabilities::DISPLAY_MULTI_CODEC, 0);
    for absent in [
        capabilities::DISPLAY_CODEC_MJPEG,
        capabilities::DISPLAY_CODEC_H264,
        capabilities::DISPLAY_STREAM_REPORT,
        capabilities::DISPLAY_SIZED_STREAM,
        capabilities::DISPLAY_COMPOSITE,
        capabilities::DISPLAY_A8_SURFACE,
    ] {
        assert_eq!(caps & absent, 0, "{absent:#x} must not be advertised");
    }
    // No bit outside the first word's known ones: CODEC_VP8 (10), CODEC_VP9
    // (13), CODEC_H265 (14) and GL_SCANOUT (7) are all absent.
    for bit in [7, 10, 13, 14] {
        assert_eq!(caps & (1 << bit), 0);
    }
}
