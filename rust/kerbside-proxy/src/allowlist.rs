//! L1 message-type grammar: is a framed message TYPE structurally valid on
//! this channel, in this direction?
//!
//! This is the compiled-in L1 allowlist table the phase-4 firewall engine
//! (`policy.rs`, step 4a) consults for every framed SPICE message. Per the
//! phase-4 plan's **Design decision 4**, which message types are structurally
//! valid on a channel is a fact about the SPICE *protocol*, not a deployment
//! policy, so the table is compiled into the proxy (derived from the ryll
//! `shakenfist-spice-protocol` constants) rather than delivered over gRPC.
//!
//! The table is built from two sources, unioned:
//!
//! 1. The ryll `logging::message_names` name tables (one `fn(u16) ->
//!    &'static str` per channel+direction). A type whose name is not the
//!    literal `"unknown"` is a modeled, known type for that channel+direction.
//! 2. An **explicit** SPICE common-base set that applies to every channel:
//!    server->client `SPICE_MSG_*` opcodes 1..=7 and client->server
//!    `SPICE_MSGC_*` opcodes 1..=6. This union is load-bearing: the ryll name
//!    tables do NOT consistently include the full common base (e.g.
//!    `inputs_client` only recognises ACK_SYNC/ACK/PONG via its `common_client`
//!    fallback, so a legitimate client `DISCONNECTING`, `MIGRATE_FLUSH_MARK`,
//!    or `MIGRATE_DATA` would otherwise be misclassified as unknown). Channel
//!    -specific opcodes begin at 101, so the base ranges never collide with
//!    channel-specific types.
//!
//! Channel coverage (Design decision 4):
//! - Main, Display, Inputs, Cursor, Playback -> their own name tables.
//! - Usbredir, Port, Webdav -> the `spicevmc` tables (these three ride the
//!   SpiceVMC message set, as documented in the ryll `constants.rs`).
//! - Record, Smartcard, Tunnel -> **no** modeled grammar. These return
//!   [`MsgClass::ChannelUnmodeled`] so the engine can apply L0-only + observe
//!   (never terminate on type) rather than treating every type as disallowed.

use shakenfist_spice_protocol::constants::{main_client, main_server};
use shakenfist_spice_protocol::logging::message_names;
use shakenfist_spice_protocol::ChannelType;

use crate::policy::Direction;

/// The sentinel the ryll `message_names` fns return for a message type that is
/// not in their table. "Known name" is defined as `name != UNKNOWN`.
const UNKNOWN: &str = "unknown";

/// First/last opcode of the SPICE common **server->client** base message set
/// (`SPICE_MSG_*`), valid on every channel. `MIGRATE`(1) .. `NOTIFY`(7) is a
/// contiguous run; cross-referenced to the ryll `main_server` constants which
/// hold these exact wire values (MIGRATE=1, MIGRATE_DATA=2, SET_ACK=3, PING=4,
/// WAIT_FOR_CHANNELS=5, DISCONNECTING=6, NOTIFY=7).
const SERVER_BASE_FIRST: u16 = main_server::MIGRATE; // 1
const SERVER_BASE_LAST: u16 = main_server::NOTIFY; // 7

/// First/last opcode of the SPICE common **client->server** base message set
/// (`SPICE_MSGC_*`), valid on every channel. `ACK_SYNC`(1) .. `DISCONNECTING`
/// (6) is a contiguous run; cross-referenced to the ryll `main_client`
/// constants (ACK_SYNC=1, ACK=2, PONG=3, MIGRATE_FLUSH_MARK=4, MIGRATE_DATA=5,
/// DISCONNECTING=6).
const CLIENT_BASE_FIRST: u16 = main_client::ACK_SYNC; // 1
const CLIENT_BASE_LAST: u16 = main_client::DISCONNECTING; // 6

/// Whether we have a modeled grammar for a (channel, direction), and if so
/// whether a given message type is in it.
///
/// The engine (step 4a) needs `ChannelUnmodeled` to be distinct from
/// `Disallowed`: an unmodeled channel gets L0-only enforcement plus observe,
/// whereas a `Disallowed` type on a modeled channel is a real grammar
/// violation the engine may terminate on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgClass {
    /// A known/valid message type for this channel+direction (either a
    /// channel-specific modeled type or a common-base type).
    Allowed,
    /// The channel+direction is modeled, but this specific type is not in its
    /// grammar (and is not a common-base type).
    Disallowed,
    /// We have no grammar table for this channel (record / smartcard / tunnel).
    ChannelUnmodeled,
}

/// Classify one framed SPICE message TYPE for a `(channel, direction)`.
///
/// This is a pure lookup over the compiled-in grammar; it inspects only the
/// message type (opcode), never the body. See the module docs for how the
/// table is built.
pub fn classify(channel: ChannelType, dir: Direction, msg_type: u16) -> MsgClass {
    match channel_table(channel, dir) {
        // Unmodeled channel: no grammar at all, regardless of type. The engine
        // treats this as L0-only + observe rather than a violation.
        None => MsgClass::ChannelUnmodeled,
        Some(name_of) => {
            if is_common_base(dir, msg_type) || name_of(msg_type) != UNKNOWN {
                MsgClass::Allowed
            } else {
                MsgClass::Disallowed
            }
        }
    }
}

/// Whether `msg_type` is a SPICE common-base opcode for this direction. These
/// apply on every channel and are checked explicitly because the ryll name
/// tables do not uniformly include them (see the module docs).
fn is_common_base(dir: Direction, msg_type: u16) -> bool {
    match dir {
        Direction::ServerToClient => (SERVER_BASE_FIRST..=SERVER_BASE_LAST).contains(&msg_type),
        Direction::ClientToServer => (CLIENT_BASE_FIRST..=CLIENT_BASE_LAST).contains(&msg_type),
    }
}

/// The ryll name-table function for a `(channel, direction)`, or `None` when
/// the channel has no modeled grammar (record / smartcard / tunnel).
///
/// The direction selects the sender's table: `ServerToClient` uses the
/// `*_server` tables (the hypervisor is the sender), `ClientToServer` the
/// `*_client` tables.
fn channel_table(channel: ChannelType, dir: Direction) -> Option<fn(u16) -> &'static str> {
    use Direction::{ClientToServer, ServerToClient};

    let name_of: fn(u16) -> &'static str = match (channel, dir) {
        (ChannelType::Main, ServerToClient) => message_names::main_server,
        (ChannelType::Main, ClientToServer) => message_names::main_client,
        (ChannelType::Display, ServerToClient) => message_names::display_server,
        (ChannelType::Display, ClientToServer) => message_names::display_client,
        (ChannelType::Inputs, ServerToClient) => message_names::inputs_server,
        (ChannelType::Inputs, ClientToServer) => message_names::inputs_client,
        (ChannelType::Cursor, ServerToClient) => message_names::cursor_server,
        (ChannelType::Cursor, ClientToServer) => message_names::cursor_client,
        (ChannelType::Playback, ServerToClient) => message_names::playback_server,
        (ChannelType::Playback, ClientToServer) => message_names::playback_client,
        // usbredir/port/webdav all ride the SpiceVMC message set.
        (ChannelType::Usbredir | ChannelType::Port | ChannelType::Webdav, ServerToClient) => {
            message_names::spicevmc_server
        }
        (ChannelType::Usbredir | ChannelType::Port | ChannelType::Webdav, ClientToServer) => {
            message_names::spicevmc_client
        }
        // No modeled grammar in the ryll crate. Tunnel is obsolete.
        (ChannelType::Record | ChannelType::Smartcard | ChannelType::Tunnel, _) => return None,
    };
    Some(name_of)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shakenfist_spice_protocol::constants::{inputs_client, main_server as ms};

    // --- Common base: allowed in BOTH directions on multiple channels. ---

    #[test]
    fn common_base_ping_server_to_client_all_channels() {
        // SPICE_MSG_PING = 4 (server->client base) on every modeled channel.
        for ch in [
            ChannelType::Main,
            ChannelType::Display,
            ChannelType::Inputs,
            ChannelType::Cursor,
        ] {
            assert_eq!(
                classify(ch, Direction::ServerToClient, 4),
                MsgClass::Allowed,
                "PING(4) server->client should be allowed on {ch:?}"
            );
        }
    }

    #[test]
    fn common_base_ack_client_to_server_all_channels() {
        // SPICE_MSGC_ACK = 2 (client->server base) on every modeled channel.
        for ch in [
            ChannelType::Main,
            ChannelType::Display,
            ChannelType::Inputs,
            ChannelType::Cursor,
        ] {
            assert_eq!(
                classify(ch, Direction::ClientToServer, 2),
                MsgClass::Allowed,
                "ACK(2) client->server should be allowed on {ch:?}"
            );
        }
    }

    // --- The base-union guard: the subtle case the name table alone gets
    //     wrong. inputs_client's name table only knows ACK_SYNC/ACK/PONG via
    //     its common_client fallback, so DISCONNECTING(6) is "unknown" there
    //     and MUST be rescued by the explicit common-base union. ---

    #[test]
    fn inputs_client_disconnecting_is_base_allowed() {
        // Sanity: the ryll name table really does miss this (proves the union
        // is load-bearing, not redundant).
        assert_eq!(message_names::inputs_client(6), "unknown");
        assert_eq!(
            classify(ChannelType::Inputs, Direction::ClientToServer, 6),
            MsgClass::Allowed
        );
    }

    #[test]
    fn client_base_full_range_allowed_on_inputs() {
        // MIGRATE_FLUSH_MARK(4) and MIGRATE_DATA(5) are also missing from the
        // inputs_client name table but valid common-base client opcodes.
        for t in CLIENT_BASE_FIRST..=CLIENT_BASE_LAST {
            assert_eq!(
                classify(ChannelType::Inputs, Direction::ClientToServer, t),
                MsgClass::Allowed,
                "client base opcode {t} should be allowed on inputs"
            );
        }
    }

    // --- Representative channel-specific types. ---

    #[test]
    fn inputs_client_mouse_and_key_allowed() {
        // The interop-bug guard (master-plan "mouse clicks not working"):
        // the inputs client mouse/key set must be allowed.
        for t in [
            inputs_client::KEY_DOWN,       // 101
            inputs_client::KEY_UP,         // 102
            inputs_client::MOUSE_MOTION,   // 111
            inputs_client::MOUSE_POSITION, // 112
            inputs_client::MOUSE_PRESS,    // 113
            inputs_client::MOUSE_RELEASE,  // 114
        ] {
            assert_eq!(
                classify(ChannelType::Inputs, Direction::ClientToServer, t),
                MsgClass::Allowed,
                "inputs_client opcode {t} should be allowed"
            );
        }
    }

    #[test]
    fn display_server_draw_and_stream_allowed() {
        // A draw op and a stream op on the bulk display server direction.
        assert_eq!(
            classify(ChannelType::Display, Direction::ServerToClient, 304), // DRAW_COPY
            MsgClass::Allowed
        );
        assert_eq!(
            classify(ChannelType::Display, Direction::ServerToClient, 123), // STREAM_DATA
            MsgClass::Allowed
        );
    }

    #[test]
    fn main_server_init_allowed() {
        assert_eq!(
            classify(ChannelType::Main, Direction::ServerToClient, ms::INIT), // 103
            MsgClass::Allowed
        );
    }

    #[test]
    fn spicevmc_data_allowed_on_usbredir_port_webdav() {
        // usbredir/port/webdav share the SpiceVMC set; DATA=101 both ways.
        for ch in [
            ChannelType::Usbredir,
            ChannelType::Port,
            ChannelType::Webdav,
        ] {
            assert_eq!(
                classify(ch, Direction::ServerToClient, 101),
                MsgClass::Allowed
            );
            assert_eq!(
                classify(ch, Direction::ClientToServer, 101),
                MsgClass::Allowed
            );
        }
    }

    // --- Disallowed: modeled channel+direction, bogus type. ---

    #[test]
    fn bogus_type_on_modeled_channel_is_disallowed() {
        assert_eq!(
            classify(ChannelType::Inputs, Direction::ClientToServer, 9999),
            MsgClass::Disallowed
        );
        assert_eq!(
            classify(ChannelType::Display, Direction::ServerToClient, 9999),
            MsgClass::Disallowed
        );
        assert_eq!(
            classify(ChannelType::Main, Direction::ServerToClient, 9999),
            MsgClass::Disallowed
        );
    }

    // --- Unmodeled channels: anything, including a base opcode, is
    //     ChannelUnmodeled (never Allowed, never Disallowed). ---

    #[test]
    fn record_channel_is_unmodeled_for_any_type() {
        for dir in [Direction::ServerToClient, Direction::ClientToServer] {
            for t in [1u16, 4, 101, 9999] {
                assert_eq!(
                    classify(ChannelType::Record, dir, t),
                    MsgClass::ChannelUnmodeled,
                    "record should be unmodeled for dir={dir:?} type={t}"
                );
            }
        }
    }

    #[test]
    fn smartcard_and_tunnel_channels_are_unmodeled() {
        for ch in [ChannelType::Smartcard, ChannelType::Tunnel] {
            for dir in [Direction::ServerToClient, Direction::ClientToServer] {
                assert_eq!(classify(ch, dir, 101), MsgClass::ChannelUnmodeled);
                assert_eq!(classify(ch, dir, 4), MsgClass::ChannelUnmodeled);
            }
        }
    }
}
