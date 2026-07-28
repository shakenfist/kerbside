# Kerbside, a SPICE VDI proxy

Kerbside is a SPICE VDI protocol proxy: a pure-Python control plane (the REST
API and the daemon) that supervises a Rust SPICE proxy. It sits out the front
of your cloud and provides VDI access to VMs running inside the cluster,
determining what VM to proxy your traffic to based on the password you
provide when connecting. Unlike layer 4 proxies that pass through unparsed
traffic, Kerbside understands the SPICE protocol itself — the proxy
terminates TLS, drives the SPICE link handshake, and is an enforcing SPICE
application firewall, on by default.

Kerbside currently knows how to proxy console sessions for Shaken Fist,
OpenStack, and oVirt. It will mostly be of interest to operators of those
clouds who want to offer users rich native SPICE desktops (high resolution,
multi-monitor, USB passthrough, audio) instead of HTML5-transcoded consoles.
OpenStack is probably the best documented integration at the moment because
there are patches to add deployment support for Kerbside to Kolla-Ansible in
the [kerbside-patches](https://github.com/shakenfist/kerbside-patches)
repository.

Kerbside is currently considered experimental: it works, but it has not yet
seen large scale deployment.

## Installation

```bash
pip install kerbside
```

This installs the Python control plane and a matching prebuilt
`kerbside-proxy` binary wheel automatically (x86_64 and aarch64). See
[docs/installation.md](https://github.com/shakenfist/kerbside/blob/develop/docs/installation.md)
for the packaging details, OS-level dependencies, and deployment pointers.

## Documentation

In the [docs/](https://github.com/shakenfist/kerbside/blob/develop/docs/index.md)
directory:

- [Documentation Index](https://github.com/shakenfist/kerbside/blob/develop/docs/index.md) - What Kerbside is, the broker model, and the connection flow
- [Installation](https://github.com/shakenfist/kerbside/blob/develop/docs/installation.md) - Packages, OS dependencies, and deployment
- [Configuration](https://github.com/shakenfist/kerbside/blob/develop/docs/configuration.md) - Configuration reference, including the SPICE firewall knobs
- [Console Sources](https://github.com/shakenfist/kerbside/blob/develop/docs/console-sources.md) - Configuring sources.yaml for Shaken Fist, OpenStack, and oVirt
- [Proxy Architecture](https://github.com/shakenfist/kerbside/blob/develop/docs/proxy-architecture.md) - Internal proxy design, state machine, and firewall
- [Database Schema](https://github.com/shakenfist/kerbside/blob/develop/docs/schema.md) - Tables, columns, and relationships
- [SPICE Protocol Documentation](https://github.com/shakenfist/kerbside/blob/develop/docs/index.md#spice-protocol-documentation) - Protocol fundamentals, link handshake, per-channel message formats, compression, capabilities, USB redirection, and the VD agent protocol (under `docs/spice/`)
- [Development](https://github.com/shakenfist/kerbside/blob/develop/docs/development.md) - Database migrations and vendored web assets
- [Testing](https://github.com/shakenfist/kerbside/blob/develop/docs/testing.md) - CI lanes, Ryll harnesses, the oVirt console probe, Tempest, and load-test images

Project reference files:

- [ARCHITECTURE.md](https://github.com/shakenfist/kerbside/blob/develop/ARCHITECTURE.md) - High-level system architecture
- [AGENTS.md](https://github.com/shakenfist/kerbside/blob/develop/AGENTS.md) - AI agent guidelines for working on this codebase
- [.claude/](https://github.com/shakenfist/kerbside/tree/develop/.claude) - Claude Code project instructions and skills (database migrations, adding source types)

## License

Apache-2.0
