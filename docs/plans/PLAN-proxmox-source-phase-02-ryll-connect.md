# Proxmox source phase 2: HTTP CONNECT in shakenfist-spice-protocol

This is the detailed plan for phase 2 of
[PLAN-proxmox-source.md](PLAN-proxmox-source.md). Read the
master plan first; its *Why this is not another `ovirt.py`*
and *What the measurements settled* sections are assumed
knowledge here, particularly the three protocol details that
"cost an afternoon".

## Prompt

All implementation for this phase lands in the
`shakenfist/ryll` repository (checkout at
`/srv/kasm_profiles/mikal/vscode/src/shakenfist/ryll`),
mostly in the `shakenfist-spice-protocol` crate, with a
smaller change to the `ryll` binary's `.vv` parsing. The
plan itself lives here in `shakenfist/kerbside/docs/plans/`,
beside its master plan, following the precedent
[PLAN-host-subject-phase-01-ryll-verifier.md](PLAN-host-subject-phase-01-ryll-verifier.md)
set. Sub-agents must be briefed accordingly: they work in
the ryll checkout, and nothing in kerbside changes in this
phase.

Before implementing, ground every claim about reference
behaviour in the reference sources rather than this plan's
paraphrase: spice-gtk's proxy URI parser is
`spice_uri_parse` in
`/srv/src-reference/spice/spice-gtk/src/spice-uri.c:108-215`,
and its use is `update_proxy` and the `open_host` path in
`spice-session.c:256-297,2089-2200`. spice-gtk hands the
actual CONNECT to GIO's `GHttpProxy`, whose source is not in
`/srv/src-reference`; fetch `gio/ghttpproxy.c` from GLib
upstream before relying on anything this plan says about it.
Consult ryll's `STYLEGUIDE.md` and `AGENTS.md` for crate
conventions, and run quality gates through the Makefile,
which wraps builds in Docker: `make lint` (rustfmt and
clippy `-D warnings`) and `make test`.

Planning effort: **high**. This phase changes the transport
path of a published crate, opens a path around the
connection's identity check if it gets the refusals wrong,
and is the protocol-level half of a two-repository change.

## Repository and branch logistics

- Repository: `shakenfist/ryll`, branch
  `spice-http-connect` off current `develop`.
- One commit per step (see *Step plan*); each commit must
  pass `make lint` and `make test` on its own.
- Landing this phase means merging to ryll `develop`. The
  master plan's Execution table records it as
  `ryll <sha> (#pr)`.
- Kerbside consumes the crate as a git dependency pinned by
  `rev` (`rust/kerbside-proxy/Cargo.toml:25`), so nothing in
  kerbside changes until phase 3b bumps the pin. The crate
  is also published to crates.io (at 0.1.7 today, per ryll's
  PLAN-crate-release), which matters for decision 9.
- Per the push-audit shared block, a phase that lands in
  another repository is audited there, as part of the pull
  request that lands it. Ryll has a `PUSH-AUDIT.md`; step 2g
  runs it. The master plan's own push-audit phase cites that
  audit rather than repeating it.

## Scope

In:

- A typed HTTP proxy address in the protocol crate, parsed
  with spice-gtk's semantics for the forms this phase
  supports.
- An HTTP CONNECT exchange performed between the TCP dial and
  the TLS wrap in `SpiceClient::connect_channel`.
- The two refusals open question 2 asked for: a tunnelled
  connection without a pinned `host_subject`, and a
  tunnelled connection without a TLS port, both fail at
  `SpiceClient::new`.
- A TLS `ServerName` that works when `host` is a Proxmox
  pseudo-hostname.
- The `ryll` binary reading the `.vv` `proxy=` key, so ryll
  can open a Proxmox-issued `.vv` directly, with no kerbside
  in the path. This is the use the operator named for doing
  the work in ryll at all.
- Keeping the pseudo-hostname, which carries a signed ticket,
  out of ryll's logs, capture metadata and bug reports.
- Fuzz targets for both new parsers, and a manual end-to-end
  proof against the validated PVE node.

Out:

- Anything in kerbside. The `Target` proto change, the pin
  bump and `backend.rs` are phase 3b.
- `https://` proxies (TLS to the proxy itself), which
  spice-gtk supports and Proxmox does not use. Parsed and
  refused with a clear error, not silently treated as
  `http`.
- Proxy authentication (`user:pass@` in the URI, or
  `Proxy-Authorization`). Also parsed and refused.
- The `SPICE_PROXY` environment variable, which spice-gtk
  falls back to when a `.vv` names no proxy. A Proxmox `.vv`
  always names one, so nothing in this plan needs it.
- A connect timeout inside the crate. `connect_channel` has
  none today and callers supply their own (kerbside wraps
  each attempt in `BACKEND_CONNECT_TIMEOUT`, `backend.rs:39`).
  A proxy that accepts and never answers hangs exactly as a
  SPICE server that stalls the link handshake does now.

## What the survey found

Surveyed 2026-09-24 against ryll `origin/develop` at
`e11ad22`. The master plan's claims about ryll hold: the dial
is at `shakenfist-spice-protocol/src/client.rs:361`, and
`ServerName` is derived from `config.host` at `:383`. Six
findings go beyond it.

1. **`ServerName` does not merely mis-identify under a
   tunnel; it fails outright.** `ServerName::try_from`
   (`client.rs:383`) accepts a DNS name or an IP address. A
   Proxmox pseudo-hostname
   (`pvespiceproxy:6aaf3e30:100:pve1:61000::0ce0...`) is
   neither, because of its colons, so every tunnelled TLS
   connection would error before the handshake started.
   Open question 2 is a correctness requirement, not a
   hardening choice.
2. **The pseudo-hostname is a credential, and ryll writes
   `host` in four places.** The crate logs `addr` at debug
   level (`client.rs:357-358`). The binary logs it at info
   level (`ryll/src/main.rs:231-236`), passes it to
   `CaptureSession::new`, which writes it into capture
   metadata (`main.rs:247-252`, `capture.rs:710-715`), and
   passes it to the bug-report observer (`main.rs:386-389`,
   and `app.rs:1121`). A bug report is exactly the artefact
   a user attaches to a public issue. The ticket inside it
   expires in about 40 seconds, so the exposure is small,
   but it is a signed credential and it should not be
   there.
3. **The address format breaks on IPv6 literals.**
   `format!("{}:{}", host, port)` (`client.rs:357`) produces
   `::1:5900` for an IPv6 host, which `TcpStream::connect`
   cannot parse. This is a pre-existing bug in the direct
   path. Step 2b rewrites that line anyway, and switching to
   the `(host, port)` tuple form fixes it for both paths.
   Recorded under *Bugs fixed during this work*.
4. **`ConnectionConfig` is built by struct literal in three
   places**, which a new field breaks: ryll's
   `From<&Config>` (`ryll/src/config.rs:412-422`), two tests
   (`client.rs:807,823`, which use `..Default::default()`
   and so survive), and kerbside's `backend.rs` (outside
   this phase). The struct derives `Default`
   (`lib.rs:85`), so a caller using functional update is
   unaffected.
5. **spice-gtk's proxy semantics are narrower than a URI
   parser.** `spice_uri_parse` defaults the scheme to
   `http` when absent, defaults the port to 3128 for `http`
   and 3129 for `https`, refuses any other scheme, strips
   trailing slashes, accepts `user:pass@`, and handles
   bracketed IPv6 hosts. A parser that follows it accepts
   every `proxy=` value a Proxmox or oVirt `.vv` carries.
6. **The fuzz target list is no longer a CI matrix.** The
   host-subject precedent added its target to a matrix in
   `ci.yml`. Nightly fuzzing now lives in `fuzz.yml`, and
   the target list is extracted from `fuzz/Cargo.toml` by
   `tools/fuzz-targets.sh`, guarded by
   `tools/test-fuzz-targets.sh`. A new `[[bin]]` in the
   manifest is picked up without editing a workflow.

The master plan's open questions 1 and 2 are settled by
decisions 1 and 4 below. This planning commit records that
at their source.

## Decisions

1. **The CONNECT lives in the crate, not in kerbside.** This
   settles open question 1 the way the master plan
   recommended: every way of reaching a SPICE server stays in
   one place, and ryll gains Proxmox support without
   kerbside. As the master plan now explains, this costs
   kerbside no inspection. The tunnel sits beneath TLS, and
   `connect_channel` still returns a plaintext `SpiceStream`.

2. **A typed proxy, parsed at the edge.** A new module
   `shakenfist-spice-protocol/src/proxy.rs` owns:
   - `pub struct HttpProxy { pub host: String, pub port: u16 }`
     for an HTTP proxy, with `host` holding a bare host (no
     brackets, even for IPv6).
   - `pub fn parse_proxy_uri(s: &str) -> Result<HttpProxy,
     ProxyError>` implementing spice-gtk's rules from finding
     5, with two deliberate refusals: an `https` scheme, and
     any userinfo. Both return an error naming the
     unsupported feature, not a generic parse failure.
   - `ProxyError` via `thiserror`, which is crate precedent.

   `ConnectionConfig` gains `pub proxy: Option<HttpProxy>`,
   not `Option<String>`. The crate never parses a URI at
   connect time; the `.vv` parser and, in phase 3b,
   kerbside's source driver parse at the boundary where the
   string arrives. A malformed `proxy=` therefore fails the
   `.vv` load and never reaches a dial.

3. **The CONNECT request matches the reference client.** The
   exchange is written by hand over the existing tokio
   `io-util` feature, so no HTTP dependency is added:
   - Request: `CONNECT <host>:<tls_port> HTTP/1.0`, then
     `Host: <host>:<tls_port>`, then a `User-Agent` naming
     the crate and version, then a blank line. Here `host`
     is `config.host`, the pseudo-hostname. Send the `Host:`
     header always: Proxmox reads the target from it, not
     from the request line
     (`PVE/APIServer/AnyEvent.pm:1559`), and a CONNECT
     without it gets a `401` that is indistinguishable from
     an expired ticket. `HTTP/1.0` is chosen to match what
     GIO's `GHttpProxy` sends for remote-viewer, which is the
     client Proxmox is tested against. Step 2a must confirm
     that against `ghttpproxy.c` before committing to it. If
     GIO sends `HTTP/1.1`, use that instead.
   - Response: read one byte at a time until `\r\n\r\n`,
     with a 16 KiB cap on the header block, so that no byte
     past the headers is consumed. Those bytes belong to TLS.
     A pure `parse_connect_response(&[u8])` interprets the
     buffered block. Only status `200` establishes the
     tunnel, again matching GIO. Any other status is an
     error carrying the status line. A `401` adds a hint
     that a Proxmox ticket is valid for about 30 seconds.
     `407` names proxy authentication as unsupported. EOF
     before the blank line, a status line that is not
     `HTTP/1.x`, and a header block over the cap are all
     errors.

4. **Tunnels are TLS-only and must be pinned, enforced at
   construction.** This settles open question 2.
   `SpiceClient::new` refuses a config where `proxy` is set
   and `host_subject` is `None`, and refuses one where
   `proxy` is set and `tls_port` is `None`. It follows the
   precedent that a malformed pin fails construction
   (`client.rs:279-290`), so a misconfigured tunnel can never
   dial.

   The pin requirement is what makes the `ServerName` choice
   safe. With `host_subject` set, `needs_spice_verifier`
   (`client.rs:257-262`) is true, so the connection uses
   `SpiceCaVerifier`, which forgives the name and enforces
   the subject. Under a tunnel, then, `ServerName` is
   **SNI** only, not an identity claim. Use the proxy's host
   (a DNS name or an IP, both valid `ServerName`s), and say
   so in a comment at the call site. qemu ignores SNI. In a
   PVE cluster the proxy may be a different node from the
   one hosting the VM, so the proxy host is not the backend's
   name either. That is exactly why the name must not become
   the identity check.

   The plaintext refusal is not about Proxmox, which only
   offers TLS here. A plaintext SPICE session through a
   third-party proxy has no identity check at all, and
   nothing needs one.

5. **One transport function, two callers' worth of
   testability.** Split `connect_channel` into a private
   `async fn open_transport(&self, use_tls, port) ->
   Result<SpiceStream>` (TCP dial, `nodelay`, keepalive,
   optional CONNECT, optional TLS wrap), then the existing
   link and auth. Behaviour without a proxy is byte-for-byte
   unchanged, apart from finding 3's fix. The split lets the
   tests drive the transport against a fake proxy and a
   rustls server without writing a fake SPICE server as
   well.

   Keepalive and `nodelay` apply to the socket to the proxy,
   which is the only socket there is.

6. **The ticket stays out of logs and artefacts.**
   `ConnectionConfig` gains `pub fn display_target(&self) ->
   String`. Without a proxy it returns `host:port`, as
   printed today. With a proxy it returns
   `<proxy host>:<proxy port> (tunnelled, target redacted)`.
   The crate's debug log uses it, and step 2c moves ryll's
   info log, capture metadata and bug-report observer onto
   it. The crate does not parse Proxmox's pseudo-hostname
   format to print something friendlier: that format belongs
   to Proxmox, and the crate treats `host` as opaque.

   This is the decision most likely to be argued with, from
   either side. One objection is that a 40-second ticket is
   not worth protecting. The other is that redacting the
   whole target also hides the vmid and node, which a
   debugger wants. The answer to the first is that a bug
   report outlives its ticket but not its reader's trust in
   what we put in it. The answer to the second is that
   Proxmox's own logs name the vmid, and a later change can
   show more once someone needs it.

7. **The `ryll` binary reads `proxy=`.** `Config` gains
   `proxy: Option<HttpProxy>`, populated by `parse_vv_content`
   (`config.rs:523-574`) from the `proxy` key through
   `filter_none` and `parse_proxy_uri`. A parse error fails
   the `.vv` load with the key name in the message. The
   `From<&Config>` impl carries it through. The existing
   `delete-this-file=1` handling already stops auto-reconnect
   for a single-use ticket, and a Proxmox `.vv` sets it, so a
   dropped session does not retry against a dead ticket.
   Step 2f confirms this rather than assuming it.

8. **Fuzzing.** Two new targets, `fuzz_parse_proxy_uri` and
   `fuzz_parse_connect_response`. Both parse bytes that come
   from a network peer or a downloaded file.

9. **The public API change is breaking, and says so.**
   Adding a field to a struct with public fields breaks any
   caller that builds it by struct literal without
   `..Default::default()`. The crate is on crates.io at
   0.1.x, so this goes in the commit message and in the
   release notes, and it bounds the next release to a minor
   version bump. Choosing that version belongs to ryll's
   release process, not this phase. `#[non_exhaustive]` was
   considered and rejected, because it would forbid
   functional update outside the crate and break every
   caller instead of some.

## Key facts front-loaded for the sub-agents

- The whole transport path is `SpiceClient::connect_channel`,
  `shakenfist-spice-protocol/src/client.rs:345-420`: address
  `:357`, TCP connect `:361`, keepalive `:364-374`, TLS wrap
  with `ServerName` `:377-387`, then link `:397` and auth
  `:414`.
- Construction and the malformed-pin refusal:
  `SpiceClient::new`, `client.rs:271-300`. Verifier
  selection: `needs_spice_verifier`, `client.rs:257-262`.
- `ConnectionConfig`: `lib.rs:77-117`, which derives
  `Default` and documents each field at length. Match that
  density for `proxy`.
- Test precedent: `client.rs:422+`, a `mod tests` using
  `rcgen` 0.14 to mint a CA and leaves with chosen subjects,
  a per-test `CryptoProvider` (`crypto_provider()`, which
  explains why it avoids the global default), and a
  `SpiceClient::new` refusal test (`:806-829`) to mirror for
  decision 4. For a real TLS server in a test, use
  `tokio_rustls::TlsAcceptor` over a `tokio::net::TcpListener`
  on `127.0.0.1:0`. tokio dev-dependency features are
  `io-util, net, macros, rt` (`Cargo.toml`), so
  `#[tokio::test]` works on the current-thread runtime.
- Test precedent for duplex streams: `link.rs` tests, which
  drive handshake code with `tokio::io::duplex`.
- `.vv` parsing: `ryll/src/config.rs:523-574`;
  `filter_none` `:426-433`; `Config` `:387-410`;
  `From<&Config>` `:412-422`.
- Places ryll prints `host`: `main.rs:231-236` (info log),
  `main.rs:247-252` into `capture.rs:710-715` (metadata),
  `main.rs:386-389` and `app.rs:1121-1122` (bug-report
  target). Check each consumer only displays the value and
  never dials it back before substituting `display_target()`.
- Fuzz manifest: `shakenfist-spice-protocol/fuzz/Cargo.toml`
  (a detached workspace, four existing `[[bin]]` blocks
  with `test = false, doc = false, bench = false`). The
  nightly list is extracted by `tools/fuzz-targets.sh`, and
  `tools/test-fuzz-targets.sh` is its guard.
- Reference semantics: `spice-uri.c:108-215` (parser),
  `spice-session.c:256-297` (`update_proxy`),
  `:2128-2200` (`proxy_lookup_ready`, which builds the
  `GProxyAddress` GIO dials).
- Proxmox specifics, from the master plan: the connect string
  travels in `Host:`, the CONNECT target port must equal
  the port signed into the pseudo-hostname
  (`PVE/Ticket.pm:168`), and the ticket is refused outside
  `-20 < age < 40` seconds (`PVE/Ticket.pm:166`).

## Step plan

One commit per step, in order:

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2a | high | opus | none | In the ryll checkout, create `shakenfist-spice-protocol/src/proxy.rs`, exported as `pub mod proxy` following the crate's style for `host_subject`. Implement decision 2 (`HttpProxy`, `parse_proxy_uri`, `ProxyError`) and decision 3's exchange as three functions: `write_connect_request(stream, target_host, target_port)`, `read_connect_response(stream)` (byte-at-a-time to `\r\n\r\n`, 16 KiB cap) and the pure `parse_connect_response(&[u8])`. First fetch GLib's `gio/ghttpproxy.c` and confirm the request line version, headers and accepted statuses GIO uses; follow it, and record in the commit message what you found. Derive the URI rules from `spice-uri.c:108-215`, not from this brief. Unit tests in the same file cover: URI parsing (bare `host`, `host:port`, `http://host:port`, default port 3128, trailing slashes, `[::1]:3128`, and errors for `https://`, `user:pass@host`, a `socks5://` scheme, a port of 0 or above 65535, a non-numeric port, an empty host, and a missing `]`); request bytes, asserted exactly, including the `Host:` header; responses over `tokio::io::duplex` (200 accepted; 401 with the ticket hint; 407; 502; EOF mid-headers; oversize header block; a non-HTTP status line); and **no over-read**, where the peer writes the response and then extra bytes, and the test asserts the extra bytes are still readable after `read_connect_response` returns. No wiring into `SpiceClient` in this step. `make lint && make test` must pass. |
| 2b | high | opus | none | Wire the proxy into the crate per decisions 4, 5, 6 and 9. Add `pub proxy: Option<HttpProxy>` to `ConnectionConfig` (`lib.rs:77-117`), documented at the density of its neighbours, including that a tunnel requires `tls_port` and `host_subject`. Add `display_target()`. In `SpiceClient::new` (`client.rs:279`), add the two refusals after the pin parse, with errors naming the missing field. Split `connect_channel` into `open_transport` plus link and auth (decision 5). Dial `(host, port)` as a tuple, not a formatted string, which fixes IPv6 literals (survey finding 3). With a proxy, dial the proxy, run the 2a exchange targeting `(config.host, tls_port)`, then wrap in TLS with `ServerName` taken from the proxy host, with a comment explaining it is SNI only and why that is safe (decision 4). Replace the debug log's `addr` with `display_target()`. Update ryll's `From<&Config>` (`ryll/src/config.rs:412`) with `proxy: None` for now; step 2c fills it in. Add tests to `client.rs`'s `mod tests`: the two refusals and their positive counterpart; `display_target()` both ways; and transport integration through a fake CONNECT proxy (a `TcpListener` task that reads the request, asserts the `Host:` header, answers 200 and splices bytes to a `TlsAcceptor` server whose leaf is minted by rcgen). The integration cases are: a matching pin completes `open_transport`; a mismatched pin fails the handshake; the proxy answering 401 surfaces the 2a error. The commit message states the breaking API change (decision 9). `make lint && make test` must pass. |
| 2c | medium | sonnet | none | In the `ryll` binary, add `proxy: Option<HttpProxy>` to `Config` (`config.rs:387`), parse the `proxy` key in `parse_vv_content` (`config.rs:523-574`) via `filter_none` then `shakenfist_spice_protocol::proxy::parse_proxy_uri`, and fail the load with an error naming the `proxy` key on a parse error. `--direct` configs get `None`. Carry it through `From<&Config>`, replacing 2b's `proxy: None`. Move every place ryll prints the target onto `ConnectionConfig::display_target()`: the info log at `main.rs:231-236`, the capture metadata host at `main.rs:247-252`, and the bug-report target at `main.rs:386-389` and `app.rs:1121`. First confirm that none of these consumers use the value to connect (read `capture.rs:710+` and the bug-report observer); stop and report if one does. Add `.vv` parser tests next to the existing ones: a Proxmox-shaped `.vv` (pseudo-hostname `host`, `tls-port`, `proxy=http://pve1.example:3128`, `host-subject`, `ca`, `delete-this-file=1`) parses with the proxy set; an absent `proxy` gives `None`; a `proxy=https://...` fails naming the key. `make lint && make test` must pass. |
| 2d | medium | sonnet | none | Add cargo-fuzz targets `fuzz_parse_proxy_uri` (feed `String::from_utf8_lossy(data)` to `parse_proxy_uri`) and `fuzz_parse_connect_response` (feed raw bytes to `parse_connect_response`). Put new files in `shakenfist-spice-protocol/fuzz/fuzz_targets/`, with `[[bin]]` blocks in `fuzz/Cargo.toml` matching the existing four exactly. Do not edit any workflow. Instead run `tools/fuzz-targets.sh` and confirm both names appear, and run `tools/test-fuzz-targets.sh`. Build both targets the way nightly does (`make fuzz-devcontainer`, then `cargo fuzz build <target>` inside it, per the existing Makefile targets), run each for 100,000 iterations, and report the command used and the result. |
| 2e | low | sonnet | none | Documentation, in ryll. In `docs/configuration.md` under *.vv File Format* (`:139+`), document the `proxy` key: the forms accepted (optional `http://`, default port 3128, bracketed IPv6), the forms refused (`https`, credentials), and that a tunnelled connection requires `tls-port` and `host-subject`. Add a short Proxmox example `.vv` with the ticket and password redacted, plus one sentence that Proxmox tickets are valid for about 30 seconds, so a Proxmox `.vv` must be opened promptly. Update the crate `README.md` only if it describes the connect path. Match the surrounding prose and keep it factual. |
| 2f | high | opus | none | **Operator-assisted validation against the private PVE 9.2.20 node.** This is not a CI step: the node is private (master plan open question 5). With a release build of the branch, use the script in *Validation against a real node* below to mint a fresh `.vv` and open it with `ryll --file <vv> --headless` inside 30 seconds. Assert that the main, display, inputs and cursor channels all authenticate. Keep the session up for 120 seconds, well past ticket expiry, and confirm it stays up. Then run the three negative checks from that section. Record each result, with timestamps, under *Outcome* in this plan file in kerbside, which becomes its own small kerbside commit. |
| 2g | high | opus | none | Run ryll's `PUSH-AUDIT.md` over the phase's branch diff against ryll `develop` before the pull request is marked ready. Fix findings on the branch, or decline them in writing in this plan's *Outcome* section with the reason. Record the result, including "no findings", in one sentence there. |

After each step the management session reviews against the
master plan's checklist. It also re-reads 2a's URI rules line
by line against `spice-uri.c`. After 2b, it re-runs the
no-proxy path of the crate's existing tests, to confirm
decision 5's "byte-for-byte unchanged" claim held.

## Validation against a real node

Step 2f runs these from a host that resolves the node's FQDN
(see the master plan's settled FQDN constraint). The token
is the validated deployment's API token. Nothing here is
committed to either repository.

```bash
#!/bin/bash
# Mint a Proxmox SPICE ticket as a .vv and open it with ryll.
# Usage: pve-spice-smoke.sh <node> <vmid> [delay-seconds]
set -euo pipefail
node="$1"; vmid="$2"; delay="${3:-0}"
vv="$(mktemp --suffix=.vv)"
curl -sf --cacert "${PVE_CA}" \
    -H "Authorization: PVEAPIToken=${PVE_TOKEN}" \
    -X POST "https://${node}:8006/api2/json/nodes/${node}/qemu/${vmid}/spiceproxy" \
  | jq -r '.data | "[virt-viewer]", (to_entries[] | "\(.key)=\(.value)")' > "${vv}"
sleep "${delay}"
exec ryll --file "${vv}" --headless --verbose
```

- **Positive:** delay 0. All channels authenticate, and the
  session survives 120 seconds.
- **Expired ticket:** delay 45. The `.vv` load succeeds, and
  the connection fails with the 401 error and its ticket
  hint from decision 3. It must not fail with a TLS or link
  error.
- **Wrong pin:** delay 0, with `host-subject` edited in the
  `.vv` (change the `CN`). The TLS handshake fails, and the
  warning names both subjects.
- **Missing pin:** delay 0, with `host-subject` removed. ryll
  refuses before dialling, with decision 4's error.

The `ca` value in the API response has escaped newlines
(master plan, *Three protocol details*). ryll's
`build_root_store` already unescapes `\n` (`client.rs:218`),
so the value is passed through as-is. Check that during the
positive run rather than assuming it.

## Risks and mitigations

- **A refusal is missed and a tunnel dials unpinned.** This
  is the failure the phase exists to prevent, and it is
  silent. Mitigation: the refusals live in `SpiceClient::new`
  and not the dial path, so every caller passes through
  them. 2b tests both refusals, and 2f's missing-pin check
  proves them against the real node. The management session
  confirms the refusal comes before `create_tls_connector`
  can run.
- **An over-read swallows the first TLS bytes.** This would
  present as an intermittent handshake failure that reads
  like a certificate problem. Mitigation: byte-at-a-time
  reads and 2a's explicit no-over-read test.
- **GIO's request format differs from this plan's
  recollection.** Mitigation: 2a reads `ghttpproxy.c` before
  writing the request, and 2f proves the result against
  Proxmox, which is the peer that matters.
- **Redaction misses a place the target is printed.**
  Mitigation: 2c's brief enumerates the four sites the
  survey found. The management session greps the ryll
  workspace for `config.host` and `.host` after 2c and
  accounts for every hit.
- **The breaking API change surprises a crates.io
  consumer.** Mitigation: decision 9's commit message and
  release note. Kerbside, the one consumer we know of, is
  on a git pin and adapts in phase 3b.

## Definition of done

- [ ] `SpiceClient::new` refuses `proxy` without
      `host_subject`, and `proxy` without `tls_port`. Two
      tests assert each error names the missing field.
- [ ] With `proxy: None`, every pre-existing crate test
      passes unchanged. No existing test was edited except
      to add `proxy` where a struct literal requires it.
- [ ] A test proves that bytes following the CONNECT
      response's blank line are still readable by the
      caller.
- [ ] `grep -rn 'config.host' ryll/src
      shakenfist-spice-protocol/src` finds no site that logs,
      writes or reports the host without going through
      `display_target()`. Any remaining hit is a dial or a
      `From` conversion.
- [ ] `tools/fuzz-targets.sh` lists `fuzz_parse_proxy_uri`
      and `fuzz_parse_connect_response`, and each ran
      100,000 iterations without a crash.
- [ ] `docs/configuration.md` documents `proxy`, and nothing
      in ryll's docs says a `.vv`'s proxy is ignored.
- [ ] All four checks in *Validation against a real node*
      are recorded under *Outcome* with their results.
- [ ] Ryll's `PUSH-AUDIT.md` has been run over the branch,
      and its result is recorded under *Outcome*.
- [ ] The ryll pull request is merged to `develop`, and the
      master plan's Execution table records
      `ryll <sha> (#pr)`.

## Bugs fixed during this work

- IPv6-literal hosts could not be dialled directly, because
  `connect_channel` formatted the address as `host:port`
  (survey finding 3). Fixed in 2b as a side effect of the
  tuple dial; 2b adds a test that dials `::1`.

## Future work

- `https://` proxies and proxy credentials, both of which
  spice-gtk supports and the parser deliberately refuses.
  Add them when a deployment needs them; the refusal errors
  name the gap.
- The `SPICE_PROXY` environment fallback, for parity with
  remote-viewer.
- A connect timeout inside the crate, for callers that are
  not kerbside.
- A friendlier `display_target()` for Proxmox, showing the
  vmid and node, if debugging demands it (decision 6).

## Outcome

Not started.

## Back brief

Before executing any step of this plan, back brief the
operator on the intended approach and on any deviation from
this plan found during implementation. In particular, if
step 2a finds that GIO's CONNECT differs from decision 3,
say so and confirm the change before step 2b builds on it.
