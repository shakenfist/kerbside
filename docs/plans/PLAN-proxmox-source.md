# Proxmox console source

## Situation

Kerbside has source drivers for oVirt, Shaken Fist and a
static fleet. Proxmox has been deferred since 2026-08-02 for
want of a driver, leaving a "no source yet" row in
`docs/index.md`'s use-case table and the feasibility research
parked in PLAN-two-tier-ci.md's future-work section — a
footnote it had outgrown. It moved here on 2026-09-20, and
that section now points at this plan.

That research was done from documentation, because there was
nowhere to test it. There is now: a single-node PVE 9.2.20 on
`debian:13`, built with Ansible and validated privately
(deploys in under ten minutes, survives a reboot, re-runs
idempotently). Everything below is measured against that node
rather than read.

This is a standalone plan because the shape of the work is
understood but none of it is scheduled, and because two of
the open questions below can invalidate the design before any
of it is written. It becomes a master plan when its first
phase is planned, which brings the mandatory push-audit phase
with it — the same promotion PLAN-use-case-docs.md went
through on 2026-09-18.

## Mission

Broker Proxmox VE SPICE consoles with the guarantees kerbside
gives every other source: a protocol-aware middle that
inspects the session, host-subject pinning on the backend
leg, and an audit trail.

Out of scope: PVE's VNC consoles, PVE clustering (a
single-node source is enough to prove the model), and the
Proxmox use-case documentation page, which belongs to
PLAN-use-case-docs.md's table and stays deferred until this
plan produces something to document.

## Why this is not another `ovirt.py`

The driver is the small half. Three layers of the existing
design assume a console can be dialled directly, and Proxmox
is the first source where that is false.

**1. The identity model has nowhere to put a tunnel.**
`BaseSource.__call__` yields `hypervisor_ip`, `insecure_port`
and `secure_port`, which `db.py`'s `Console` row stores and
`rpc/servicer.py` hands to the proxy. Proxmox binds qemu's
SPICE listener to loopback on the node with mandatory TLS;
the only way in is an HTTP CONNECT through `spiceproxy` on
port 3128, whose pseudo-hostname carries the ticket, the
vmid, the node and the port. There is no address to store in
those columns.

**2. Both credentials are minted per request, and the row
has one field to hold them.** `rpc/servicer.py` builds the
`Target` from the stored console row, `ticket` included. That
row is not as stale as it looks: it is refreshed at
token-issue time rather than at discovery. For oVirt,
`ConsolesProxyVirtViewer` fetches a fresh ticket, writes it
with `db.store_console_ticket()`, and only then mints the
kerbside token the client will connect with
(`api.py:480-527`). The authorize path never calls a driver,
and on this design it does not need to.

Proxmox should be able to reuse that shape, and this plan
assumes it will. What it cannot reuse is the shape of what
gets stored: PVE returns a SPICE password *and* a CONNECT
pseudo-hostname naming the ticket, the vmid, the node and the
port, so `Console.ticket` alone cannot carry a target.

The pattern also has a precondition that oVirt's ticket
lifetime evidently satisfies: the credential must outlive the
gap between the client fetching its `.vv` and actually
connecting. Whether a PVE ticket does is open question 2 —
and if it does not, minting has to move into
`AuthorizeConnection`, which would be the first time that
path ever called a source driver.

Here is what the call actually returns, from the validated
node:

```json
{
  "type": "spice",
  "proxy": "http://pve1.example:3128",
  "host": "pvespiceproxy:6aaf3e30:100:pve1:61000::0ce019e3c7...",
  "tls-port": 61000,
  "password": "<40 hex characters, redacted>",
  "host-subject": "OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve1.example",
  "ca": "-----BEGIN CERTIFICATE-----\n..."
}
```

`host` is not a hostname. `proxy` is where the CONNECT goes,
`host-subject` and `ca` are the pinning material — the same
shape the oVirt driver already consumes — and `password` is
the SPICE ticket. One call yields everything a driver needs.

**3. The dialer is in another repository.**
`rust/kerbside-proxy/src/backend.rs` builds a
`ConnectionConfig` and hands it to `SpiceClient`, and the
dial itself is ryll's, at
`shakenfist-spice-protocol/src/client.rs:361`: a
`TcpStream::connect`, keepalives, an optional TLS wrap, then
the link handshake and auth. The CONNECT has to happen
between the TCP dial and the TLS wrap, which is inside that
function. This is the PLAN-host-subject shape again — a ryll
change first, a kerbside adoption second — and it is why the
transport work, not the driver, is what gates a Proxmox
source.

## Open questions

These are ordered by how much they can move the design.

**1. Does one PVE ticket authorise every channel of a
session?** SPICE opens a separate TCP connection per channel,
so a session is several CONNECTs. If a ticket is single-use,
the authorize path must mint one per channel and questions 3
and 4 change shape entirely. The inference from the outside
is that it does not need to: `remote-viewer` works against
PVE today and opens many channels from one `.vv`. That is
evidence, not a measurement, and it must be measured before
anything is designed on top of it.

**2. How long is a ticket valid?** This decides whether
Proxmox can reuse the mint-at-token-issue pattern oVirt
already uses, or whether minting must move into
`AuthorizeConnection` and teach that path to call a driver.
Measure it against a running node; do not take a number from
a forum post.

**3. Where does the CONNECT live — ryll or kerbside?** Either
`ConnectionConfig` grows an optional proxy, and
`connect_channel` performs the CONNECT before the TLS wrap;
or the crate grows an entry point that accepts an
already-connected stream and kerbside does the CONNECT
itself. The recommendation is ryll: it keeps every way of
reaching a SPICE server in one place, and ryll is itself a
client that someone will eventually want to point at a
Proxmox console directly. The cost is that a deployment
concern lands in a protocol crate.

**4. What is the TLS `ServerName` inside the tunnel?**
`connect_channel` derives it from `config.host`, which under
a tunnel is the CONNECT pseudo-hostname and not a DNS name at
all. Host-subject pinning already substitutes for hostname
verification, and PVE always supplies a subject, so the pin
is the identity check — but the crate must then *refuse* a
tunnelled connection that has no `host_subject`, rather than
quietly ending up with no identity check on the backend leg.
Both directions want a test, as PLAN-host-subject did.

**5. Does `Target` grow a field or a transport sub-message?**
Either way it is a proto change, and proto changes carry the
contract-hash handshake from PLAN-proxy-dev-releases phase 3,
so the daemon and the proxy binary have to ship together.

**6. What is the least-privileged API account?** The
validated deployment uses `PVEVMUser` on `/vms` plus
`PVEAuditor` on `/`, with a `privsep=0` API token. That works;
it is not proven minimal, and the same honesty the oVirt
use-case page applies to `SuperUser` applies here.

**7. Where does a CI lane get a node?** PLAN-two-tier-ci's
future work puts a Proxmox lane in the merge tier. The
Ansible that builds the validated node lives in a private
repository, so a public lane needs either a public
equivalent or a different approach.

One constraint is already settled and is not an open
question: **the node's FQDN is load-bearing on our side.**
PVE derives the node certificate from it, and every ticket
carries both a `proxy` URL naming it and a `host-subject` to
pin against. A node whose domain does not resolve for the
broker hands out a proxy address that cannot be dialled and a
subject that will not match. Any lane must give its node a
resolvable domain rather than an invented one — which is a
bug the private deployment hit, and fixed, before it worked.

## Proposed phases

A sketch of the decomposition, not a schedule. Nothing is
scheduled until the plan is promoted, and phase 1 exists
because it can change everything after it.

| Phase | Intent |
|-------|--------|
| 1. Ticket semantics | Measure ticket lifetime and whether one ticket serves every channel of a session. Answers open questions 1 and 2, and settles where minting has to happen |
| 2. Tunnelled transport in ryll | CONNECT support on the backend dial, with the `ServerName` and no-`host_subject` refusal decided and tested both ways |
| 3. Kerbside adoption | `Target`/proto change, a console row that can carry a tunnel target and not just a password, and `backend.rs` passing the tunnel through |
| 4. The source driver | `kerbside/sources/proxmox.py`: discovery over `/nodes/{node}/qemu`, console details over `spiceproxy`, CA and subject handling |
| 5. CI lane | A lane that proves an end-to-end proxied session, per open question 7 |
| 6. Docs | The use-case page PLAN-use-case-docs.md has been holding a row for, plus `console-sources.md` |

Phases 1 and 2 land in other places than kerbside — phase 1
against a deployment, phase 2 in `shakenfist/ryll` — and a
phase that lands in another repository is audited there, as
the push-audit block requires.

## Relationship to other plans

- **PLAN-two-tier-ci.md** — where the feasibility research
  was done and still lives, now pointing here. Its future
  work also proposes the Proxmox CI lane that phase 5 would
  build.
- **PLAN-use-case-docs.md** — holds the deferred Proxmox
  page; phase 6 is what unblocks that row.
- **PLAN-host-subject.md** — the precedent for a ryll change
  adopted by kerbside, and the origin of the pinning this
  source depends on more heavily than any other.
- **PLAN-proxy-dev-releases.md** — its phase 3 contract hash
  is why a `Target` change couples the daemon and the binary.

## Status

Proposed. No phase is scheduled and no work has begun.
