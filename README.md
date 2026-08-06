# relay

A lightweight DNS proxy with rule-based routing. Designed to work standalone as a system DNS server or as an upstream DNS for other tools such as [mihomo](https://github.com/MetaCubeX/mihomo) and [sing-box](https://github.com/SagerNet/sing-box).

## Features

- **Multiple upstream protocols** — UDP, TCP, DoT, DoH, DoQ, DHCP
- **Rule-based routing** — route domains to different upstreams based on `.drs` rulesets
- **Binary rulesets** — compact FST-based format, built from mihomo YAML or AdGuard filter lists
- **Static hosts** — override specific domains locally
- **LRU cache** — with configurable min/max TTL clamping
- **Firewall redirect** — optional nftables/iptables/pf rules to intercept hard-coded DNS
- **resolv.conf management** — writes and restores `/etc/resolv.conf` on start/stop

---

## Installation

Download the latest binary for your platform from the [Releases](../../releases) page.

```bash
# Linux amd64
curl -Lo relay https://github.com/evecus/relay/releases/latest/download/relay-linux-amd64
chmod +x relay
sudo mv relay /usr/local/bin/

# Linux arm64
curl -Lo relay https://github.com/evecus/relay/releases/latest/download/relay-linux-arm64
chmod +x relay
sudo mv relay /usr/local/bin/
```

Verify the checksum:

```bash
curl -L https://github.com/evecus/relay/releases/latest/download/sha256sums.txt | sha256sum -c
```

---

## Quick Start

### Minimal — act as a system DNS server

```toml
# /etc/relay/config.toml
[dns]
listen             = "127.0.0.1:53"
manage-resolv-conf = true

[dns.upstream.default]
servers = ["tls://8.8.8.8", "tls://1.1.1.1"]
```

```bash
sudo relay run -c /etc/relay/config.toml
```

### As an upstream for mihomo / sing-box

Run relay on a non-privileged port. No root required, no resolv.conf changes.

```toml
# /etc/relay/config.toml
[dns]
listen = "127.0.0.1:5353"

[dns.upstream.default]
servers = ["tls://8.8.8.8"]
```

Then point mihomo at it:

```yaml
# mihomo config.yaml
dns:
  enable: true
  nameserver:
    - "127.0.0.1:5353"
```

---

## Ruleset Files

relay uses `.drs` (DNS Ruleset) binary files for routing rules. They are built from human-readable source files using the `relay build` command.

### Supported input formats

| Format | Flag | Rule syntax |
|--------|------|-------------|
| mihomo YAML | `--format mihomo` | `- domain.com` / `- '+.domain.com'` |
| AdGuard filter list | `--format adguard` | `\|\|domain.com^` |

### Build a ruleset

**From a mihomo YAML payload file:**

```bash
relay build \
  --input gfw.yaml \
  --format mihomo \
  --output gfw.drs
```

Example `gfw.yaml`:

```yaml
payload:
  - google.com          # exact match
  - '+.youtube.com'     # suffix match (youtube.com and all subdomains)
  - '+.googleapis.com'
  - DOMAIN,github.com
  - DOMAIN-SUFFIX,twitter.com
```

**From an AdGuard filter list:**

```bash
relay build \
  --input adguard-dns-filter.txt \
  --format adguard \
  --output ads.drs
```

Supported AdGuard syntax:

```
||ads.example.com^          → suffix match
||tracker.io^               → suffix match
@@||whitelist.com^          → ignored (whitelist entries are skipped)
! comment                   → ignored
/regex/                     → ignored (regex rules are not supported)
```

**Merge multiple files into one ruleset:**

```bash
relay build \
  --input base.yaml \
  --input extra.yaml \
  --format mihomo \
  --output merged.drs
```

All input files must use the same format. Rules from all files are merged and deduplicated.

### Inspect a ruleset

```bash
# Show metadata
relay info gfw.drs

# Output:
# File:           gfw.drs
# Build time:     2025-01-15 10:30:00 UTC
# Source hash:    a3f2c1b8e4d70912
# Exact domains:  42
# Suffix rules:   1337
# Total rules:    1379

# Test whether a domain matches
relay lookup gfw.drs google.com
# MATCH  DOMAIN        google.com

relay lookup gfw.drs sub.youtube.com
# MATCH  DOMAIN-SUFFIX  sub.youtube.com

relay lookup gfw.drs baidu.com
# NO MATCH              baidu.com
```

---

## Configuration Reference

See [`config.toml`](config.toml) for a fully annotated template.

### `[dns]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string | — | Listen address, e.g. `"127.0.0.1:53"` |
| `manage-resolv-conf` | bool | `false` | Manage `/etc/resolv.conf`. Only valid when port is 53 |

### `[dns.upstream.<name>]`

The group named `default` is required and used as the fallback.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `servers` | list | — | Upstream server URLs |
| `strategy` | string | `round-robin` | `round-robin` or `fastest` |

**Upstream URL schemes:**

| Scheme | Example | Notes |
|--------|---------|-------|
| `udp://` | `udp://8.8.8.8` | Standard DNS/UDP |
| `tcp://` | `tcp://8.8.8.8` | Standard DNS/TCP |
| `tls://` | `tls://8.8.8.8` | DNS over TLS (port 853) |
| `https://` | `https://dns.google/dns-query` | DNS over HTTPS |
| `quic://` | `quic://dns.adguard.com` | DNS over QUIC (port 853) |
| `dhcp://` | `dhcp://eth0` | Use DNS from DHCP lease on interface |
| `rcode://` | `rcode://refused` | Return a fixed response code |

**`fastest` strategy** sends the query to all servers simultaneously and uses the first response. Consumes more upstream bandwidth but minimizes latency.

### `[[dns.rules]]`

Rules are evaluated top to bottom. The first matching rule wins.

| Key | Type | Description |
|-----|------|-------------|
| `rulesets` | list of paths | `.drs` files to match against (OR semantics) |
| `upstream` | string | Forward to this upstream group |
| `action` | string | `"reject"` returns NXDOMAIN immediately |

### `[dns.hosts]`

```toml
[dns.hosts]
"router.local"    = "192.168.1.1"
"dev.example.com" = "127.0.0.1"
```

### `[dns.cache]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enable` | bool | `true` | Enable LRU cache |
| `size` | int | `4096` | Max number of cached responses |
| `min-ttl` | int | `60` | Clamp record TTL up to this value (seconds) |
| `max-ttl` | int | `86400` | Clamp record TTL down to this value (seconds) |

### `[dns.firewall]`

Optional. Requires root. Installs firewall rules on startup, removes them on exit.

> **Note:** If upstreams use plain `udp://` or `tcp://` on port 53, enabling localhost hijack will cause a routing loop. Use `tls://`, `https://`, or `quic://` upstreams to avoid this.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enable` | bool | `false` | Install firewall redirect rules |
| `backend` | string | `"auto"` | `auto`, `nftables`, `iptables`, or `pf` |
| `localhost-hijack` | bool | `true` | Intercept DNS from this machine (OUTPUT chain) |
| `lan-hijack` | bool | `false` | Intercept DNS from LAN devices (PREROUTING chain) |
| `lan-cidr` | string | — | Restrict LAN hijack to this CIDR, e.g. `"192.168.1.0/24"` |
| `lan-interface` | string | — | Restrict LAN hijack to this interface, e.g. `"eth0"` |

---

## Usage Examples

### Split domestic and international DNS

```toml
[dns]
listen             = "127.0.0.1:53"
manage-resolv-conf = true

[dns.upstream.default]
servers  = ["tls://8.8.8.8", "tls://1.1.1.1"]

[dns.upstream.china]
servers  = ["udp://223.5.5.5", "udp://119.29.29.29"]

[[dns.rules]]
rulesets = ["/etc/relay/rules/ads.drs"]
action   = "reject"

[[dns.rules]]
rulesets = ["/etc/relay/rules/cn.drs"]
upstream = "china"
```

Build the rulesets (run once, re-run when upstream lists update):

```bash
# China domains — use mihomo's CN list
relay build \
  --input cn.yaml \
  --format mihomo \
  --output /etc/relay/rules/cn.drs

# Ad blocking — use AdGuard DNS filter
curl -o adguard.txt https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
relay build \
  --input adguard.txt \
  --format adguard \
  --output /etc/relay/rules/ads.drs
```

### Intercept hard-coded DNS (firewall redirect)

Programs that hard-code `8.8.8.8` bypass the system resolver. Use firewall redirect to capture them. Use DoT/DoH upstreams to avoid routing loops.

```toml
[dns]
listen             = "127.0.0.1:53"
manage-resolv-conf = true

[dns.upstream.default]
servers = ["tls://8.8.8.8"]    # DoT — not affected by port-53 redirect

[dns.firewall]
enable           = true
localhost-hijack = true
```

### Soft router / LAN gateway

Run relay on a machine that acts as the default gateway. Intercept DNS from all LAN clients.

```toml
[dns]
listen             = "0.0.0.0:53"
manage-resolv-conf = true

[dns.upstream.default]
servers = ["tls://8.8.8.8"]

[dns.upstream.china]
servers = ["udp://223.5.5.5"]

[[dns.rules]]
rulesets = ["/etc/relay/rules/cn.drs"]
upstream = "china"

[dns.firewall]
enable         = true
lan-hijack     = true
lan-cidr       = "192.168.1.0/24"
lan-interface  = "eth0"
```

Enable IP forwarding:

```bash
sysctl -w net.ipv4.ip_forward=1
# Make permanent:
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-relay.conf
```

---

## Run as a systemd Service

```ini
# /etc/systemd/system/relay.service
[Unit]
Description=relay DNS proxy
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/relay run -c /etc/relay/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now relay
sudo systemctl status relay
```

---

## Subcommand Reference

```
relay run    -c <config>                          Run the DNS proxy
relay build  --input <file> [--input <file>...]   Build a .drs ruleset
               --format <mihomo|adguard>
               --output <file>
relay lookup <ruleset.drs> <domain>               Test a domain against a ruleset
relay info   <ruleset.drs>                        Show ruleset metadata
```

---

## Building from Source

```bash
git clone https://github.com/evecus/relay
cd relay
cargo build --release
# Binary at: target/release/relay
```

Requires Rust 1.85 or later.
