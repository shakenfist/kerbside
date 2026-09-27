//! SPICE link capabilities on both legs of a proxied channel.
//!
//! The proxy answers the client's link itself, before it knows which
//! backend the client will be authorized to reach: the reply carries the
//! RSA key the client encrypts its ticket to, so it cannot wait for the
//! backend. The capabilities Kerbside offers the client are therefore a
//! fixed set per channel type, [`reply_channel_caps`], taken from what
//! spice-server itself advertises for that channel type and masked to
//! what Kerbside relays.
//!
//! In the other direction, the client's own capabilities are forwarded to
//! the backend ([`backend_common_caps`] and the client's channel caps
//! verbatim), so spice-server encodes for the client actually connected
//! rather than for whatever the proxy's own SPICE client would advertise
//! (kerbside#477).
//!
//! Kerbside relays every message opaquely, framed by the 6-byte mini
//! header, so the only capability it depends on is MINI_HEADER, plus
//! AUTH_SELECTION for the client-leg ticket exchange it performs itself.
//! A client lacking either is refused at link time
//! ([`missing_required_client_caps`]).
//!
//! Every opcode the offered channel capabilities enable is admitted by
//! the L1 allowlist (`allowlist.rs`), which a test below checks.

use shakenfist_spice_protocol::constants::capabilities;
use shakenfist_spice_protocol::ChannelType;

/// Common capabilities offered to the client: AUTH_SELECTION, AUTH_SPICE
/// and MINI_HEADER (bits 0, 1 and 3; word value 11).
///
/// spice-server sets MINI_HEADER and AUTH_SELECTION on every channel
/// (`server/red-channel.cpp:128-129`) and then AUTH_SPICE, or AUTH_SASL
/// instead when SASL is enabled (`server/reds.cpp:1480-1488`). Kerbside
/// only performs SPICE ticket authentication on the client leg, so it
/// never offers AUTH_SASL.
pub const REPLY_COMMON_CAPS: [u32; 1] =
    [capabilities::AUTH_SELECTION | capabilities::AUTH_SPICE | capabilities::MINI_HEADER];

/// The capability words a client advertised in its link message, carried
/// from the client leg to the backend leg.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientCaps {
    pub common: Vec<u32>,
    pub channel: Vec<u32>,
}

/// spice-protocol `SPICE_PLAYBACK_CAP_VOLUME` (`spice/protocol.h`).
const PLAYBACK_VOLUME: u32 = 1 << 1;
/// spice-protocol `SPICE_PLAYBACK_CAP_OPUS`.
const PLAYBACK_OPUS: u32 = 1 << 3;
/// spice-protocol `SPICE_RECORD_CAP_VOLUME`.
const RECORD_VOLUME: u32 = 1 << 1;
/// spice-protocol `SPICE_RECORD_CAP_OPUS`.
const RECORD_OPUS: u32 = 1 << 2;
/// spice-protocol `SPICE_INPUTS_CAP_KEY_SCANCODE`.
const INPUTS_KEY_SCANCODE: u32 = 1 << 0;

/// Main channel: `server/main-channel.cpp:220-223` sets
/// SEMI_SEAMLESS_MIGRATE, NAME_AND_UUID, AGENT_CONNECTED_TOKENS and
/// SEAMLESS_MIGRATE.
const MAIN_CAPS: [u32; 1] = [capabilities::MAIN_SEMI_SEAMLESS_MIGRATE
    | capabilities::MAIN_NAME_AND_UUID
    | capabilities::MAIN_AGENT_CONNECTED_TOKENS
    | capabilities::MAIN_SEAMLESS_MIGRATE];

/// Display channel: `server/display-channel.cpp:2228-2231` sets
/// MONITORS_CONFIG, PREF_COMPRESSION, PREF_VIDEO_CODEC_TYPE and
/// STREAM_REPORT. The streaming-agent display channel
/// (`server/stream-channel.cpp:397-399`) sets a subset of these.
const DISPLAY_CAPS: [u32; 1] = [capabilities::DISPLAY_MONITORS_CONFIG
    | capabilities::DISPLAY_PREF_COMPRESSION
    | capabilities::DISPLAY_PREF_VIDEO_CODEC_TYPE
    | capabilities::DISPLAY_STREAM_REPORT];

/// Inputs channel: `server/inputs-channel.cpp:534` sets KEY_SCANCODE.
const INPUTS_CAPS: [u32; 1] = [INPUTS_KEY_SCANCODE];

/// Playback channel: `server/sound.cpp:1188` sets VOLUME, and
/// `server/sound.cpp:1104-1109` (via `spice_server_set_playback_rate`,
/// 1117-1120) sets OPUS when spice-server is built with Opus and the
/// device runs at the Opus rate, which qemu requests.
const PLAYBACK_CAPS: [u32; 1] = [PLAYBACK_VOLUME | PLAYBACK_OPUS];

/// Record channel: `server/sound.cpp:1202` sets VOLUME, and
/// `server/sound.cpp:1104-1109` (via `spice_server_set_record_rate`,
/// 1127-1130) sets OPUS under the same conditions as playback.
const RECORD_CAPS: [u32; 1] = [RECORD_VOLUME | RECORD_OPUS];

/// usbredir, port and webdav channels are all `RedVmcChannel`s
/// (`server/spicevmc.cpp:151-170`), whose constructor sets
/// DATA_COMPRESS_LZ4 when built with LZ4, the default
/// (`server/spicevmc.cpp:139-141`). Port channels carry no other
/// capability: PORT_INIT and PORT_EVENT are not capability-gated.
const SPICEVMC_CAPS: [u32; 1] = [capabilities::SPICEVMC_LZ4];

/// The channel capabilities Kerbside offers the client for `channel_type`
/// in its link reply.
///
/// Cursor (`server/cursor-channel.cpp`) and smartcard
/// (`server/smartcard.cpp`) set no channel capabilities, and tunnel is
/// obsolete, so those offer none.
pub fn reply_channel_caps(channel_type: ChannelType) -> &'static [u32] {
    match channel_type {
        ChannelType::Main => &MAIN_CAPS,
        ChannelType::Display => &DISPLAY_CAPS,
        ChannelType::Inputs => &INPUTS_CAPS,
        ChannelType::Playback => &PLAYBACK_CAPS,
        ChannelType::Record => &RECORD_CAPS,
        ChannelType::Usbredir | ChannelType::Port | ChannelType::Webdav => &SPICEVMC_CAPS,
        ChannelType::Cursor | ChannelType::Smartcard | ChannelType::Tunnel => &[],
    }
}

/// The common capabilities Kerbside requires of a client's link message,
/// that `common_caps` lacks, by name.
///
/// - MINI_HEADER: the relay frames both legs on the 6-byte mini header,
///   and forwards the client's caps, so the backend uses it too. A client
///   without it would send the 18-byte full header and break framing.
/// - AUTH_SELECTION: the client-leg ticket read (`read_auth_ticket`)
///   expects an auth mechanism selector before the ticket, which a client
///   only sends when it advertised this.
pub fn missing_required_client_caps(common_caps: &[u32]) -> Vec<&'static str> {
    let word0 = common_caps.first().copied().unwrap_or(0);
    let mut missing = Vec::new();
    if word0 & capabilities::AUTH_SELECTION == 0 {
        missing.push("AUTH_SELECTION");
    }
    if word0 & capabilities::MINI_HEADER == 0 {
        missing.push("MINI_HEADER");
    }
    missing
}

/// The common capabilities to advertise to the backend for a client that
/// advertised `client_common_caps` (which must already have passed
/// [`missing_required_client_caps`]).
///
/// Forwarded verbatim except for the authentication mechanism bits: the
/// backend authenticates Kerbside, not the client, and Kerbside only does
/// SPICE ticket authentication. So AUTH_SPICE is set and AUTH_SASL is
/// cleared; forwarding a client's AUTH_SASL would make a SASL-enabled
/// spice-server skip the ticket key pair (`server/reds.cpp:1582-1583`)
/// that Kerbside's ticket is encrypted to.
pub fn backend_common_caps(client_common_caps: &[u32]) -> Vec<u32> {
    let mut caps = client_common_caps.to_vec();
    if caps.is_empty() {
        caps.push(0);
    }
    caps[0] = (caps[0] & !capabilities::AUTH_SASL) | capabilities::AUTH_SPICE;
    caps
}

/// Capability bit numbers set in `offered` but not in `granted`.
///
/// Used to spot a backend that lacks a capability Kerbside already
/// offered the client: bit `n` of word `w` is reported as `32 * w + n`,
/// the numbering spice-protocol's `SPICE_*_CAP_*` enums use.
pub fn missing_caps(offered: &[u32], granted: &[u32]) -> Vec<u32> {
    let mut missing = Vec::new();
    for (word_index, word) in offered.iter().enumerate() {
        let have = granted.get(word_index).copied().unwrap_or(0);
        let lacking = word & !have;
        for bit in 0..32u32 {
            if lacking & (1 << bit) != 0 {
                missing.push(word_index as u32 * 32 + bit);
            }
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::allowlist::{classify, MsgClass};
    use crate::policy::Direction;

    const ALL_CHANNELS: [ChannelType; 11] = [
        ChannelType::Main,
        ChannelType::Display,
        ChannelType::Inputs,
        ChannelType::Cursor,
        ChannelType::Playback,
        ChannelType::Record,
        ChannelType::Tunnel,
        ChannelType::Smartcard,
        ChannelType::Usbredir,
        ChannelType::Port,
        ChannelType::Webdav,
    ];

    /// The reply table, as wire words, per channel type. Pinned
    /// explicitly so a change to it is a deliberate edit here too.
    #[test]
    fn reply_caps_table() {
        assert_eq!(REPLY_COMMON_CAPS, [11]);
        let expected: &[(ChannelType, &[u32])] = &[
            // SEMI_SEAMLESS_MIGRATE, NAME_AND_UUID,
            // AGENT_CONNECTED_TOKENS, SEAMLESS_MIGRATE: bits 0-3.
            (ChannelType::Main, &[0xf]),
            // MONITORS_CONFIG(1), STREAM_REPORT(4),
            // PREF_COMPRESSION(6), PREF_VIDEO_CODEC_TYPE(12).
            (
                ChannelType::Display,
                &[(1 << 1) | (1 << 4) | (1 << 6) | (1 << 12)],
            ),
            (ChannelType::Inputs, &[1]),
            (ChannelType::Cursor, &[]),
            // VOLUME(1), OPUS(3).
            (ChannelType::Playback, &[(1 << 1) | (1 << 3)]),
            // VOLUME(1), OPUS(2).
            (ChannelType::Record, &[(1 << 1) | (1 << 2)]),
            (ChannelType::Tunnel, &[]),
            (ChannelType::Smartcard, &[]),
            (ChannelType::Usbredir, &[1]),
            (ChannelType::Port, &[1]),
            (ChannelType::Webdav, &[1]),
        ];
        assert_eq!(expected.len(), ALL_CHANNELS.len());
        for (channel, words) in expected {
            assert_eq!(
                reply_channel_caps(*channel),
                *words,
                "{} reply caps",
                channel.name()
            );
        }
    }

    /// Kerbside only performs SPICE ticket authentication, so the reply
    /// must never offer SASL, and must grant what the relay depends on.
    #[test]
    fn reply_common_caps_offer_spice_auth_and_mini_header_only() {
        let word = REPLY_COMMON_CAPS[0];
        assert_eq!(word & capabilities::AUTH_SASL, 0);
        assert!(missing_required_client_caps(&REPLY_COMMON_CAPS).is_empty());
        assert_ne!(word & capabilities::AUTH_SPICE, 0);
    }

    /// Every client->server opcode a reply capability lets the client
    /// send, and every server->client opcode it announces, must be
    /// admitted by the L1 allowlist, or the firewall would observe (or,
    /// when enforcing, terminate on) traffic the proxy itself invited.
    /// Record is unmodeled in the allowlist (L0 and observe only).
    #[test]
    fn reply_caps_enable_only_allowlisted_opcodes() {
        use shakenfist_spice_protocol::constants::{
            display_client, display_server, inputs_client, main_client, main_server,
            playback_server, spicevmc_client, spicevmc_server,
        };
        use Direction::{ClientToServer, ServerToClient};
        // (channel, capability bit mask, opcodes it gates, direction).
        let gated: &[(ChannelType, u32, &[u16], Direction)] = &[
            // STREAM_REPORT: SPICE_MSGC_DISPLAY_STREAM_REPORT and
            // SPICE_MSG_DISPLAY_STREAM_ACTIVATE_REPORT.
            (
                ChannelType::Display,
                capabilities::DISPLAY_STREAM_REPORT,
                &[display_client::STREAM_REPORT],
                ClientToServer,
            ),
            (
                ChannelType::Display,
                capabilities::DISPLAY_STREAM_REPORT,
                &[display_server::STREAM_ACTIVATE_REPORT],
                ServerToClient,
            ),
            // PREF_COMPRESSION: SPICE_MSGC_DISPLAY_PREFERRED_COMPRESSION.
            (
                ChannelType::Display,
                capabilities::DISPLAY_PREF_COMPRESSION,
                &[display_client::PREFERRED_COMPRESSION],
                ClientToServer,
            ),
            // PREF_VIDEO_CODEC_TYPE:
            // SPICE_MSGC_DISPLAY_PREFERRED_VIDEO_CODEC_TYPE.
            (
                ChannelType::Display,
                capabilities::DISPLAY_PREF_VIDEO_CODEC_TYPE,
                &[display_client::PREFERRED_VIDEO_CODEC_TYPE],
                ClientToServer,
            ),
            // MONITORS_CONFIG: SPICE_MSG_DISPLAY_MONITORS_CONFIG.
            (
                ChannelType::Display,
                capabilities::DISPLAY_MONITORS_CONFIG,
                &[display_server::MONITORS_CONFIG],
                ServerToClient,
            ),
            // KEY_SCANCODE: SPICE_MSGC_INPUTS_KEY_SCANCODE.
            (
                ChannelType::Inputs,
                INPUTS_KEY_SCANCODE,
                &[inputs_client::KEY_SCANCODE],
                ClientToServer,
            ),
            // NAME_AND_UUID: SPICE_MSG_MAIN_NAME, SPICE_MSG_MAIN_UUID.
            (
                ChannelType::Main,
                capabilities::MAIN_NAME_AND_UUID,
                &[main_server::NAME, main_server::UUID],
                ServerToClient,
            ),
            // AGENT_CONNECTED_TOKENS: SPICE_MSG_MAIN_AGENT_CONNECTED_TOKENS.
            (
                ChannelType::Main,
                capabilities::MAIN_AGENT_CONNECTED_TOKENS,
                &[main_server::AGENT_CONNECTED_TOKENS],
                ServerToClient,
            ),
            // SEAMLESS_MIGRATE: the seamless migration handshake.
            (
                ChannelType::Main,
                capabilities::MAIN_SEAMLESS_MIGRATE,
                &[
                    main_server::MIGRATE_BEGIN_SEAMLESS,
                    main_server::MIGRATE_DST_SEAMLESS_ACK,
                    main_server::MIGRATE_DST_SEAMLESS_NACK,
                ],
                ServerToClient,
            ),
            (
                ChannelType::Main,
                capabilities::MAIN_SEAMLESS_MIGRATE,
                &[
                    main_client::MIGRATE_DST_DO_SEAMLESS,
                    main_client::MIGRATE_CONNECTED_SEAMLESS,
                ],
                ClientToServer,
            ),
            // SEMI_SEAMLESS_MIGRATE: SPICE_MSG_MAIN_MIGRATE_BEGIN.
            (
                ChannelType::Main,
                capabilities::MAIN_SEMI_SEAMLESS_MIGRATE,
                &[main_server::MIGRATE_BEGIN],
                ServerToClient,
            ),
            // Playback VOLUME: SPICE_MSG_PLAYBACK_VOLUME and _MUTE.
            // OPUS changes the payload of DATA, not the opcode set.
            (
                ChannelType::Playback,
                PLAYBACK_VOLUME,
                &[playback_server::VOLUME, playback_server::MUTE],
                ServerToClient,
            ),
        ];
        for (channel, cap, opcodes, dir) in gated {
            assert_ne!(
                reply_channel_caps(*channel)[0] & cap,
                0,
                "{} test row names a capability the reply does not offer",
                channel.name()
            );
            for opcode in *opcodes {
                assert_eq!(
                    classify(*channel, *dir, *opcode),
                    MsgClass::Allowed,
                    "{} {dir:?} opcode {opcode} is gated by an offered cap but not allowlisted",
                    channel.name()
                );
            }
        }
        // DATA_COMPRESS_LZ4: SPICE_MSG(C)_SPICEVMC_COMPRESSED_DATA on
        // every SpiceVMC channel type.
        for channel in [
            ChannelType::Usbredir,
            ChannelType::Port,
            ChannelType::Webdav,
        ] {
            assert_ne!(
                reply_channel_caps(channel)[0] & capabilities::SPICEVMC_LZ4,
                0
            );
            assert_eq!(
                classify(channel, ServerToClient, spicevmc_server::COMPRESSED_DATA),
                MsgClass::Allowed
            );
            assert_eq!(
                classify(channel, ClientToServer, spicevmc_client::COMPRESSED_DATA),
                MsgClass::Allowed
            );
        }
        // Record's caps gate record messages the allowlist does not model.
        assert_eq!(
            classify(ChannelType::Record, ClientToServer, 101),
            MsgClass::ChannelUnmodeled
        );
    }

    #[test]
    fn required_client_caps() {
        let ok = capabilities::AUTH_SELECTION | capabilities::MINI_HEADER;
        assert!(missing_required_client_caps(&[ok]).is_empty());
        assert!(missing_required_client_caps(&[ok, 0xffff_ffff]).is_empty());
        assert_eq!(
            missing_required_client_caps(&[capabilities::AUTH_SELECTION]),
            vec!["MINI_HEADER"]
        );
        assert_eq!(
            missing_required_client_caps(&[capabilities::MINI_HEADER]),
            vec!["AUTH_SELECTION"]
        );
        assert_eq!(
            missing_required_client_caps(&[]),
            vec!["AUTH_SELECTION", "MINI_HEADER"]
        );
    }

    #[test]
    fn backend_common_caps_forward_all_but_the_auth_mechanism() {
        let client = [
            capabilities::AUTH_SELECTION
                | capabilities::AUTH_SASL
                | capabilities::MINI_HEADER
                | (1 << 20),
            0x8000_0001,
        ];
        assert_eq!(
            backend_common_caps(&client),
            vec![
                capabilities::AUTH_SELECTION
                    | capabilities::AUTH_SPICE
                    | capabilities::MINI_HEADER
                    | (1 << 20),
                0x8000_0001,
            ]
        );
        assert_eq!(backend_common_caps(&[11]), vec![11]);
    }

    #[test]
    fn missing_caps_numbers_bits_across_words() {
        assert!(missing_caps(&[0b1010], &[0b1110]).is_empty());
        assert_eq!(missing_caps(&[0b1010], &[0b0010]), vec![3]);
        assert_eq!(missing_caps(&[0, 1 << 5], &[0]), vec![37]);
        assert!(missing_caps(&[], &[0xffff]).is_empty());
    }
}
