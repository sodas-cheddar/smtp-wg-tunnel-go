# smtp-wg-tunnel

WireGuard traffic carried inside an SMTP/STARTTLS conversation on port 587.

This project presents a normal mail-server exchange to the network, then
switches into TLS and carries encrypted WireGuard frames inside that channel.
It is designed for environments where outbound SMTP/STARTTLS is allowed but
direct VPN traffic is not.

---

## Contents

1. [How it works](#how-it-works)
2. [Requirements](#requirements)
3. [VPS setup](#vps-setup)
4. [Windows client setup](#windows-client-setup)
5. [Modes of operation](#modes-of-operation)
6. [Configuration reference](#configuration-reference)
7. [Performance](#performance)
8. [Troubleshooting](#troubleshooting)
9. [Security](#security)
10. [File overview](#file-overview)

---

## How it works

### Connection flow

A client starts with a valid SMTP greeting and upgrades the session with
STARTTLS:

```text
→  220 mail.example.com ESMTP Postfix
←  EHLO client.local
→  250 ... STARTTLS ...
←  STARTTLS
→  220 Ready to start TLS
```

After TLS is established, both sides authenticate using an HMAC-SHA256 token.
Once authenticated, the connection switches into tunnel mode and carries
length-prefixed WireGuard frames.

### Architecture

```text
Your machine                         Port 587 / TLS                     VPS
─────────────────────────────────    ─────────────────────    ──────────────────────
App traffic
  │
 TUN adapter (wintun)
  │
 wireguard-go (embedded)  ─── encrypted WireGuard frames ──→  server.go
  │  encrypts/decrypts                                             │
  │                                                           UDP to local wg0
  └─── decrypted packets ──── server.go ─────────────────→  wg0 → internet
```

The server receives WireGuard frames over TLS and forwards them as UDP to the
local `wg0` interface. From `wg0`'s perspective, it is talking to a normal
WireGuard peer. The VPS kernel handles routing and NAT for outbound traffic.

### Why embedded wireguard-go?

WireGuard-Windows uses Windows Filtering Platform (WFP) callouts, which add
per-packet overhead. This project embeds `wireguard-go` directly, so the
WireGuard crypto runs in-process and avoids the extra WFP path.

In loopback benchmarking, embedded mode was measured at significantly higher
throughput than the legacy UDP proxy path.

---

## Requirements

| Component | Requirement |
|---|---|
| VPS | Linux VPS with a public IP; Ubuntu 20.04+ recommended |
| Client | Windows 10/11 64-bit, PowerShell as Administrator |
| Go | 1.21+ on the Windows machine to build the client binary |
| wintun.dll | Installed automatically with WireGuard-Windows, or available from wintun.net |

---

## VPS setup

Perform the following steps on the VPS.

### 1. Install WireGuard

```bash
sudo apt update && sudo apt install -y wireguard wireguard-tools
```

### 2. Generate keys

```bash
sudo mkdir -p /etc/wireguard/keys && sudo chmod 700 /etc/wireguard/keys
cd /etc/wireguard/keys

# Server keypair
wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key

# Client keypair
wg genkey | sudo tee client_private.key | wg pubkey | sudo tee client_public.key

sudo chmod 600 /etc/wireguard/keys/*.key
```

Print all four values and save them for later:

```bash
for k in server_private server_public client_private client_public; do
  echo "=== $k ===" && sudo cat /etc/wireguard/keys/${k}.key
done
```

### 3. Configure `wg0`

Find your outbound network interface:

```bash
ip route get 1.1.1.1 | grep -oP 'dev \K\S+'
```

Create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address    = 10.0.0.1/24
ListenPort = 51820

# Replace eth0 with your actual outbound interface
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; \
           iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; \
           iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; \
           iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; \
           iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400

[Peer]
PublicKey  = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

The `--set-mss 1400` rule reduces the chance of fragmentation as traffic
leaves the VPS through a standard 1500-byte MTU.

Start the interface and enable it on boot:

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
sudo wg show
```

### 4. Enable IP forwarding

```bash
echo "net.ipv4.ip_forward=1"          | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 5. Open the firewall

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 587/tcp
sudo ufw enable
```

Port `51820/UDP` stays closed externally. Only `server.go` talks to it over
loopback.

### 6. Generate TLS certificates

Copy the project files onto the VPS, then build the binary and generate certs:

```bash
go build -o smtp-wg-tunnel .
sudo mkdir -p /etc/smtp-wg-tunnel/certs
./smtp-wg-tunnel generate-certs mail.yourdomain.com -o /etc/smtp-wg-tunnel/certs/
```

This produces four PEM files. Copy `ca.crt` to the Windows machine. The other
three stay on the VPS.

> Use the VPS hostname or a dynamic-DNS name such as DuckDNS or FreeDNS.
> If you only have an IP address, use that as the hostname argument. You can
> then omit `ca_cert` on the client to skip certificate verification.

### 7. Create a user

```bash
./smtp-wg-tunnel add-user mygamingpc
```

Copy the printed `secret` and place it into `/etc/smtp-wg-tunnel/users.yaml`:

```yaml
users:
  mygamingpc:
    secret: "paste-secret-here"
```

### 8. Create the server config

`/etc/smtp-wg-tunnel/server_config.yaml`:

```yaml
server:
  host:       "0.0.0.0"
  port:       587
  hostname:   "mail.yourdomain.com"   # must match the certificate CN/SAN
  cert_file:  "/etc/smtp-wg-tunnel/certs/server.crt"
  key_file:   "/etc/smtp-wg-tunnel/certs/server.key"
  wg_host:    "127.0.0.1"
  wg_port:    51820
  users_file: "/etc/smtp-wg-tunnel/users.yaml"
```

### 9. Run the server

Test it manually:

```bash
sudo ./smtp-wg-tunnel server -c /etc/smtp-wg-tunnel/server_config.yaml
```

Install it as a systemd service:

```bash
sudo tee /etc/systemd/system/smtp-wg-tunnel.service << 'UNIT'
[Unit]
Description=SMTP WireGuard Tunnel Server
After=network.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
ExecStart=/opt/smtp-wg-tunnel/smtp-wg-tunnel server -c /etc/smtp-wg-tunnel/server_config.yaml
WorkingDirectory=/opt/smtp-wg-tunnel
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now smtp-wg-tunnel
```

---

## Windows client setup

### 1. Install Go and build

```powershell
winget install GoLang.Go
```

Open a new PowerShell window in the project folder:

```powershell
go mod tidy
go build -o smtp-wg-tunnel.exe .
```

### 2. Create `wg0.conf`

Use the keys from the VPS setup.

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address    = 10.0.0.2/32
DNS        = 1.1.1.1
MTU        = 1380

[Peer]
PublicKey            = <SERVER_PUBLIC_KEY>
AllowedIPs           = 0.0.0.0/0, ::/0
PersistentKeepalive  = 25

# Endpoint is ignored in --wg mode; the SMTP tunnel is the transport.
Endpoint = 0.0.0.0:51820
```

`AllowedIPs = 0.0.0.0/0, ::/0` enables full-tunnel routing. For split tunnel,
replace it with the prefixes you want routed through the VPN.

### 3. Create `client_config.yaml`

```yaml
client:
  server_host:     "mail.yourdomain.com"
  server_port:     587
  username:        "mygamingpc"
  secret:          "paste-secret-here"
  ca_cert:         "ca.crt"          # path to the CA cert copied from the VPS
  reconnect_delay: 5
```

### 4. Run the client

Run PowerShell as Administrator, then start the tunnel:

```powershell
.\smtp-wg-tunnel.exe client -c client_config.yaml --wg wg0.conf
```

Expected output:

```text
Creating TUN interface (MTU 1380)…
TUN interface: wg0
Bypass route added: 1.2.3.4 via 192.168.1.1
Embedded wireguard-go active — no WireGuard-Windows app needed
✓ Tunnel established — WireGuard mode active
[wg] peer(AbCd…) - Sending handshake initiation
[wg] peer(AbCd…) - Received handshake response
stats  ul=0.0 Mbps  dl=0.0 Mbps  wg_pps=0  (bind: sent=2 drops=0)
```

Once `Received handshake response` appears, the VPN is active.

---

## Modes of operation

### Embedded wireguard-go (recommended)

```powershell
smtp-wg-tunnel.exe client -c client_config.yaml --wg wg0.conf
```

WireGuard runs entirely inside the binary. No WireGuard-Windows app is needed,
and the TUN adapter is created directly via wintun.

### Legacy UDP proxy

```powershell
smtp-wg-tunnel.exe client -c client_config.yaml
```

This mode acts as a UDP↔TLS proxy. It requires WireGuard-Windows with
`Endpoint = 127.0.0.1:51820`. Use this only if the embedded mode fails.

---

## Configuration reference

### `server_config.yaml`

| Key | Default | Description |
|---|---|---|
| `host` | `0.0.0.0` | Bind address |
| `port` | `587` | TCP listen port |
| `hostname` | — | SMTP greeting hostname; must match the TLS cert |
| `cert_file` | — | Path to the server TLS certificate |
| `key_file` | — | Path to the server TLS private key |
| `wg_host` | `127.0.0.1` | WireGuard interface address |
| `wg_port` | `51820` | WireGuard UDP port |
| `users_file` | `users.yaml` | User database |

### `client_config.yaml`

| Key | Default | Description |
|---|---|---|
| `server_host` | — | VPS hostname or IP |
| `server_port` | `587` | Must match the server |
| `username` | — | User name created with `add-user` |
| `secret` | — | Shared secret from `add-user` |
| `ca_cert` | — | Path to the CA cert; omit to skip server verification |
| `local_wg_host` | `127.0.0.1` | UDP proxy bind address (legacy mode) |
| `local_wg_port` | `51820` | UDP proxy port (legacy mode) |
| `reconnect_delay` | `5` | Seconds between reconnect attempts |

### `users.yaml`

```yaml
users:
  alice:
    secret: "64-char hex string"
  bob:
    secret: "..."
```

Generate entries with:

```bash
./smtp-wg-tunnel add-user <username>
```

---

## Performance

### Throughput

With embedded `wireguard-go`:

| Direction | Typical | Ceiling |
|---|---:|---:|
| Download | 100–115 Mbps | ~150 Mbps |
| Upload | 100–150 Mbps | ~150 Mbps |

With the legacy UDP proxy:

| Direction | Typical |
|---|---:|
| Download | 90–110 Mbps |
| Upload | ~25 Mbps |

### Stats output

The binary prints a stats line every 5 seconds:

```text
stats  ul=98.4 Mbps  dl=112.1 Mbps  wg_pps=8913  (bind: sent=8917 drops=0)
```

| Field | Meaning |
|---|---|
| `ul` | Upload throughput forwarded from WireGuard to the server |
| `dl` | Download throughput forwarded from the server to WireGuard |
| `wg_pps` | WireGuard packets per second in the upload direction |
| `bind: sent` | Cumulative `Send()` calls from `wireguard-go` |
| `bind: drops` | Packets dropped because the output buffer was full |

If `wg_pps` is high but `ul` is low, the TLS sender may be dropping batches.
If `bind: sent` is `0`, `wireguard-go` has not sent anything yet.

### VPS tuning

```bash
cat >> /etc/sysctl.conf << 'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sudo sysctl -p
```

If `grep -c aes /proc/cpuinfo` returns `0`, the VPS CPU lacks AES-NI. The
server prefers ChaCha20-Poly1305 automatically, so no manual change is needed.

---

## Troubleshooting

### “Access is denied” during TUN creation

Run PowerShell as Administrator.

### “The system cannot find the file specified” during TUN creation

`wintun.dll` is missing. Install WireGuard-Windows, or copy `wintun.dll` from
wintun.net into the same directory as `smtp-wg-tunnel.exe`.

### Connection refused or timeout on port 587

Check that the server is running and the firewall allows `587/tcp`:

```bash
sudo systemctl status smtp-wg-tunnel
sudo ufw status
```

### “Authentication credentials invalid”

`username` or `secret` in `client_config.yaml` does not match `users.yaml`.
Regenerate the user entry with `add-user` and update both files.

### Handshake retries with `wg_pps=0`

`wireguard-go` is sending but not receiving a response. Common causes:

1. `wg0` is not running on the VPS.
2. The public keys are swapped or mismatched.
3. The VPS cannot route packets back through `wg0`.

Verify the key mapping:

```bash
cat /etc/wireguard/keys/server_public.key   # goes in client wg0.conf
cat /etc/wireguard/keys/client_public.key   # goes in VPS wg0.conf [Peer]
```

### No internet after connecting in full-tunnel mode

The bypass route for the SMTP server was not added automatically. Add it
manually:

```powershell
# Get the VPS IP
[System.Net.Dns]::GetHostAddresses("mail.yourdomain.com") | Select -ExpandProperty IPAddressToString

# Get your default gateway
(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort RouteMetric | Select -First 1).NextHop

# Add the bypass route (run as Administrator)
route add <VPS_IP> mask 255.255.255.255 <GATEWAY_IP>
```

To keep it after reboot:

```powershell
route -p add <VPS_IP> mask 255.255.255.255 <GATEWAY_IP>
```

---

## Security

**Authentication** — HMAC-SHA256 with a per-user 256-bit secret. Tokens
include a Unix timestamp and are rejected outside a ±5-minute window, which
helps prevent replay attacks.

**Transport** — TLS 1.2+ with ChaCha20-Poly1305 preferred over AES-GCM.
ChaCha20 is constant-time and does not depend on AES-NI.

**Double encryption** — WireGuard encrypts the inner traffic, and TLS adds a
second independent layer. Both would need to fail for the payload to be
exposed.

**WireGuard port isolation** — The `wg0` interface binds only to
`127.0.0.1:51820`, so it is not reachable from the internet.

**Certificate pinning** — Set `ca_cert` in `client_config.yaml` to the CA
certificate generated during setup. The client rejects servers not signed by
that CA.

---

## File overview

```text
smtp-wg-tunnel/
├── main.go          Entry point and subcommand dispatch
├── common.go        HMAC auth tokens and frame codec
├── config.go        YAML config parsing
├── server.go        SMTP server, TLS, and WireGuard bridge
├── client.go        SMTP client, reconnect loop, tunnel goroutines
├── wireguard.go     Embedded wireguard-go, tunnelBind, and TUN setup
├── certs.go         ECDSA P-256 certificate generation
├── go.mod           Module definition
├── server_config.yaml
├── client_config.yaml
└── users.yaml
```
