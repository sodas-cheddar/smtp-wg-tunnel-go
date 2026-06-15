# smtp-wg-tunnel

WireGuard over SMTP-disguised TLS — a small, dependency-free Go tool for
tunneling WireGuard UDP traffic through a TLS connection that looks like an
SMTP submission server (port 587) to network inspection. Useful when a
network allows outbound "mail" traffic but blocks or throttles VPN protocols.

The project has two halves:

- **server** — runs on your VPS. Accepts TLS connections disguised as SMTP,
  authenticates clients, and forwards their traffic to a WireGuard server
  running locally on the same machine.
- **client** — runs on your laptop/phone/router. Opens a local UDP socket
  that your WireGuard client points at, wraps that traffic in TLS, and sends
  it to the server.

This tool does **not** replace WireGuard — you still need WireGuard
configured on both ends. It only provides an obfuscated transport between
them.

## Requirements

- Go 1.21+ (no external dependencies — `go build` is all you need)
- A domain name pointing at your VPS (a free DuckDNS / No-IP / FreeDNS
  hostname works fine) — the TLS certificate's hostname must match this
- WireGuard already installed and configured on the VPS and on your client
  device

## Build

```bash
git clone https://github.com/sodas-cheddar/smtp-wg-tunnel-go.git
cd smtp-wg-tunnel-go
go build -o smtp-wg-tunnel .                   # Linux / macOS
GOOS=windows go build -o smtp-wg-tunnel.exe .  # cross-compile for Windows
```

## Server setup (VPS)

### 1. Generate certificates

Pure Go — no `openssl` needed:

```bash
./smtp-wg-tunnel generate-certs -o . mail.yourserver.duckdns.org
```

> **Flag order matters.** Put `-o <dir>` *before* the hostname. Go's flag
> parser stops reading flags at the first positional argument, so
> `generate-certs <hostname> -o dir` silently writes to the current directory
> instead of `dir`.

This writes four files:

| File | Purpose |
|---|---|
| `server.crt` | Server certificate — stays on the VPS |
| `server.key` | Server private key — stays on the VPS, keep secret |
| `ca.crt` | CA certificate — copy to every client |
| `ca.key` | CA private key — stays on the VPS, keep secret |

### 2. Add a user

Add one entry per device that will connect:

```bash
./smtp-wg-tunnel add-user laptop
```

This prints a `users.yaml` snippet (for the server) and a
`client_config.yaml` snippet (for that client). Paste each into the right
file — nothing is written automatically. Repeat for each additional device.

### 3. Edit `server_config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 587                                # 587 or 465 disguise well; 25 is often blocked
  hostname: "mail.yourserver.duckdns.org"  # must match cert CN/SAN
  cert_file: "server.crt"
  key_file: "server.key"
  wg_host: "127.0.0.1"                     # where your real WireGuard server listens
  wg_port: 51820
  users_file: "users.yaml"
```

### 4. Run it

Open the chosen port (587 or 465) in your VPS firewall / cloud security
group, then:

```bash
sudo ./smtp-wg-tunnel server -c server_config.yaml
```

`sudo` is required because ports below 1024 need root on Linux. A healthy
startup looks like:

```
Listening on 0.0.0.0:587 (SMTP/STARTTLS disguise)
WireGuard target: 127.0.0.1:51820
SMTP hostname: mail.yourserver.duckdns.org | users: 1
```

## Client setup

### 1. Copy `ca.crt`

Copy `ca.crt` from the server to the client machine.

### 2. Edit `client_config.yaml`

```yaml
client:
  server_host: "mail.yourserver.duckdns.org"
  server_port: 587
  local_wg_host: "127.0.0.1"
  local_wg_port: 51820
  username: "laptop"
  secret: "<secret printed by add-user>"
  ca_cert: "ca.crt"      # set to null to disable verification (not recommended)
  reconnect_delay: 5
```

### 3. Run it

```bash
./smtp-wg-tunnel client -c client_config.yaml
```

It prints the local socket WireGuard should connect to:

```
WireGuard proxy on UDP 127.0.0.1:51820
WireGuard peer config: Endpoint = 127.0.0.1:51820 | MTU = 1380 | PersistentKeepalive = 25
```

## WireGuard configuration

In your WireGuard config, point the peer endpoint at the tunnel client and
use the suggested MTU/keepalive:

```ini
[Interface]
MTU = 1380

[Peer]
Endpoint = 127.0.0.1:51820   # matches local_wg_host:local_wg_port
PersistentKeepalive = 25
```

Bring the interface up as usual (`wg-quick up wg0`). With `smtp-wg-tunnel
client` running, WireGuard's packets are wrapped in TLS, sent to the VPS,
unwrapped, and forwarded to the real WireGuard server.

## CLI reference

```
smtp-wg-tunnel server -c server_config.yaml        Run the VPS-side tunnel server
smtp-wg-tunnel client -c client_config.yaml        Run the local WireGuard proxy
smtp-wg-tunnel generate-certs <hostname> [-o dir]  Generate TLS certificates
smtp-wg-tunnel add-user <username>                 Print a new user entry
smtp-wg-tunnel version                             Print version info
```

Both `server` and `client` shut down cleanly on Ctrl+C (SIGINT/SIGTERM).

## Notes

- Keep `ca.key` and `server.key` private and on the VPS only.
- Each device should get its own entry via `add-user` so access can be
  revoked individually by removing it from `users.yaml`.
- If the connection drops, the client retries after `reconnect_delay`
  seconds.
