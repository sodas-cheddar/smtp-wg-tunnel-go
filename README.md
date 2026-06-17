# smtp-wg-tunnel

Tunnels **WireGuard UDP** through a **SMTP-disguised TLS TCP** connection.

Deep-packet inspection sees ordinary email submission traffic (port 587 + STARTTLS + AUTH).
Inside that tunnel rides your WireGuard VPN — optimised for gaming and streaming.

---

## How it works

```
[Your machine]                            [VPS]
                                                          ┌──────────────┐
 wg0 (kernel) ──UDP──► client.py ──TCP/TLS/SMTP──────► server.py ──UDP──► wg0 (kernel)
              ◄──UDP── client.py ◄──TCP/TLS/SMTP────── server.py ◄──UDP──
```

1. **Pre-TLS** — Plaintext SMTP greeting + `EHLO` + `STARTTLS` (exactly what DPI expects on port 587)
2. **TLS upgrade** — `ssl.wrap_socket()` on both sides; everything after this is encrypted
3. **Post-TLS** — `EHLO` + `AUTH PLAIN` (HMAC-SHA256 token) + custom `WGTUNNEL` command, all invisible to DPI
4. **Tunnel mode** — Each WireGuard UDP datagram is wrapped in a 2-byte length-prefixed frame and streamed over the TLS connection. Packet boundaries are fully preserved.

### I/O model

Both sockets run fully non-blocking. Incoming WireGuard packets are drained and queued into an output buffer; a `flush_out()` helper sends as much as the TLS socket will accept *right now* via `send()` — never `sendall()` — leaving any remainder for the next writable signal from `select()`.

`SSLWantReadError` / `SSLWantWriteError` are raised by TLS for routine background activity (session-ticket rotation, key updates) on **either** `recv()` or `send()`. Both are subclasses of `ssl.SSLError`, so a naive `except ssl.SSLError` treats them as fatal — this is handled correctly everywhere: they simply mean "nothing to do this round, try again."

The output buffer is capped at 2 MB. If the link can't keep up, the newest packet is dropped rather than adding latency — WireGuard handles loss at a higher layer, same as over any lossy network.

---

## Requirements

- Python 3.8+ on both machines
- `openssl` CLI (for cert generation)
- WireGuard tools (`wg`, `wg-quick`) installed on both ends
- A domain name pointing to your VPS (free: [DuckDNS](https://www.duckdns.org), No-IP, FreeDNS)

```bash
pip install -r requirements.txt   # just PyYAML
```

---

## Server setup (VPS)

### 1 — Set up WireGuard

If `wg0` isn't already configured, set it up now — **this is the actual VPN**; smtp-wg-tunnel only carries its packets in disguise.

**Generate keypairs for both ends:**
```bash
mkdir -p /etc/wireguard/keys && cd /etc/wireguard/keys
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

**Find your main network interface** (needed for NAT):
```bash
ip route get 1.1.1.1 | grep -oP 'dev \K\S+'
```
Prints something like `eth0` or `ens3` — use it below.

**Create `/etc/wireguard/wg0.conf`:**
```ini
[Interface]
PrivateKey = <contents of server_private.key>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <contents of client_public.key>
AllowedIPs = 10.0.0.2/32
```
Swap `eth0` for whatever the previous command printed.

**Enable IP forwarding** (lets the VPS route your traffic out to the internet):
```bash
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
sysctl -p
```

**Bring it up:**
```bash
wg-quick up wg0
wg show     # one peer listed, "latest handshake: (none)" until the client connects
```

### 2 — Generate TLS certificates

```bash
python generate_certs.py mail.yourserver.duckdns.org --output certs/
```

Copy `certs/ca.crt` to your client machine. Keep `server.key` and `ca.key` secret.

### 3 — Configure

Edit `server_config.yaml`:
```yaml
server:
  hostname:  "mail.yourserver.duckdns.org"   # must match cert CN/SAN
  cert_file: "certs/server.crt"
  key_file:  "certs/server.key"
  wg_host:   "127.0.0.1"
  wg_port:   51820
```

### 4 — Add a user

```bash
python server.py --add-user mygamingpc
```

Paste the printed block into `users.yaml`, note the secret for client config.

### 5 — Open the firewall

```bash
apt install -y ufw      # if not already installed
ufw allow OpenSSH
ufw allow 587/tcp
ufw enable
```

`51820/udp` stays blocked from the outside by ufw's default-deny — only `server.py` ever talks to it, over loopback.

### 6 — Run (or install as a service)

```bash
python server.py -c server_config.yaml
```

**systemd service** (`/etc/systemd/system/smtp-wg-tunnel.service`):
```ini
[Unit]
Description=SMTP WireGuard Tunnel Server
After=network.target wg-quick@wg0.service

[Service]
ExecStart=/usr/bin/python3 /opt/smtp-wg-tunnel/server.py -c /opt/smtp-wg-tunnel/server_config.yaml
WorkingDirectory=/opt/smtp-wg-tunnel
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now smtp-wg-tunnel
```

---

## Client setup (your machine)

### 1 — Create your WireGuard config

Print the two keys you need (generated on the VPS above):
```bash
cat /etc/wireguard/keys/client_private.key
cat /etc/wireguard/keys/server_public.key
```

Save as `wg0.conf` on the client:
```ini
[Interface]
PrivateKey = <client_private.key contents>
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = <server_public.key contents>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
```

> **MTU 1380** — accounts for WireGuard + TLS + framing overhead; prevents fragmentation stutter.
> **Endpoint = 127.0.0.1** — points WireGuard at `client.py` instead of the real VPS.
> **PersistentKeepalive = 25** — keeps the WireGuard session alive across tunnel reconnects.

### 2 — Fix full-tunnel routing — do this *before* activating WireGuard

With `AllowedIPs = 0.0.0.0/0, ::/0`, WireGuard routes **all** traffic through the tunnel — including `client.py`'s own connection to your VPS. The moment WireGuard activates, that connection becomes part of "everything," loops back on itself, and dies (on Windows this shows up as the `client.py` window disconnecting or `wg` reporting "connected" with no working sites).

Normally WireGuard auto-excludes the VPN server's real IP from this routing. Here it can't — as far as WireGuard knows, the "server" is `127.0.0.1`, so it has no idea the *real* server (your VPS) also needs an exception.

**Fix — add a `/32` host route for your VPS's real IP via your normal gateway, once:**

1. Find your current default gateway:
   - **Windows:** `ipconfig` → "Default Gateway" under your active adapter
   - **Linux/macOS:** `ip route show default`

2. Find your VPS's real IP (skip if `server_host` is already an IP):
   ```bash
   nslookup mail.yourserver.duckdns.org
   ```

3. Add the route (do this **before** bringing the WireGuard tunnel up):
   - **Windows** (Administrator cmd/PowerShell):
     ```cmd
     route add <VPS_IP> mask 255.255.255.255 <GATEWAY_IP>
     ```
   - **Linux:**
     ```bash
     sudo ip route add <VPS_IP>/32 via <GATEWAY_IP>
     ```

A `/32` is more specific than `0.0.0.0/0`, so it always wins regardless of what WireGuard adds — `client.py`'s connection stays on your normal internet path, and everything else routes through `wg0`.

### 3 — Configure smtp-wg-tunnel

Edit `client_config.yaml`:
```yaml
client:
  server_host:   "mail.yourserver.duckdns.org"
  server_port:   587
  local_wg_host: "127.0.0.1"
  local_wg_port: 51820
  username:      "mygamingpc"
  secret:        "<paste secret from server --add-user output>"
  ca_cert:       "ca.crt"     # path to the ca.crt you copied from the server
```

### 4 — Start the tunnel, then bring up WireGuard

```bash
# Terminal 1 — keep this running
python client.py -c client_config.yaml

# Terminal 2, once client shows "Tunnel established"
wg-quick up wg0
```

**Order matters**: start `client.py` first so the local UDP port is ready before WireGuard tries to send its first handshake.

### 5 — Optional: run as a systemd service (Linux)

```ini
[Unit]
Description=SMTP WireGuard Tunnel Client
After=network-online.target
Before=wg-quick@wg0.service

[Service]
ExecStart=/usr/bin/python3 /opt/smtp-wg-tunnel/client.py -c /opt/smtp-wg-tunnel/client_config.yaml
WorkingDirectory=/opt/smtp-wg-tunnel
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now smtp-wg-tunnel-client
systemctl enable --now wg-quick@wg0
```

---

## Performance tuning

| Setting | Effect |
|---|---|
| `MTU = 1380` in WireGuard | Prevents fragmentation stutter |
| `PersistentKeepalive = 25` | Fast handshake recovery after reconnect |
| `TCP_NODELAY` (set automatically) | Frames sent immediately, no Nagle batching |
| 4 MB socket buffers (set automatically) | Absorbs 4K/streaming bursts |
| TCP keepalive, 10 s idle (set automatically) | Detects dead connections fast |
| Non-blocking output buffer, 2 MB cap | Drops newest packet instead of adding latency under load |
| UDP→TCP packet batching | Collapses many small writes into fewer TLS records/syscalls |
| Keepalive frames every 20 s | Holds NAT mapping alive without WireGuard overhead |
| Auto-reconnect on client | Dropped TCP session recovers in `reconnect_delay` seconds |

**Inherent TCP-over-UDP tradeoff**: wrapping WireGuard's UDP in TCP adds head-of-line blocking if a TCP segment is lost. This is the cost of DPI evasion. On a well-routed path (low loss) the latency impact is negligible.

### VPS-side tuning (no code changes)

**BBR congestion control** — handles the extra latency/jitter from TLS wrapping much better than the default CUBIC:
```bash
sysctl net.ipv4.tcp_congestion_control   # check current value

cat >> /etc/sysctl.conf << 'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL
sysctl -p
```

**Raise the initial congestion window** — raises the slow-start ceiling for any new/short-lived connection:
```bash
ip route show default
# note the gateway + device, e.g.: default via 45.76.0.1 dev eth0

ip route change default via <gateway> dev <device> initcwnd 30 initrwnd 30
```
Non-persistent across reboots — re-apply after a reboot, or script it via `/etc/network/if-up.d/`.

### If throughput is still capped: check for AES-NI

A budget VPS vCPU without AES-NI makes AES-GCM (OpenSSL's usual default) dramatically slower than ChaCha20-Poly1305 — every packet pays a heavy software-AES tax.

```bash
cat /proc/cpuinfo | grep -m1 -o aes      # empty output = no AES-NI
openssl speed -elapsed -evp aes-128-gcm 2>&1 | tail -1
openssl speed -elapsed -evp chacha20-poly1305 2>&1 | tail -1
```

If ChaCha20-Poly1305 comes back several times faster, the TLS context's cipher preference needs to shift toward it — open an issue / ask if you hit this, since it's a one-line change to `common.py`'s `make_server_ssl_ctx` / `make_client_ssl_ctx`.

---

## Debug logging

Run either side with `-d` for per-hop visibility into every WireGuard packet:

```bash
python server.py -c server_config.yaml -d
python client.py -c client_config.yaml -d
```

Each packet logs as it crosses each hop, e.g. on the client:
```
UDP←WG     148 bytes  ← ('127.0.0.1', 60149)   # received from local WireGuard
TCP→UDP    148 bytes  → ('127.0.0.1', 51820)   # forwarded to the other side
```

If packets stop appearing partway through this chain (client `UDP←WG` → server `TCP→UDP` → server `UDP←WG` → client `TCP→UDP`), that tells you exactly where to look:

- Stops after client `UDP←WG` → packet never reaches the server — tunnel transport issue.
- Reaches server `TCP→UDP` (sent to `wg0`) but server never logs `UDP←WG` in response → `wg0` isn't replying — almost always a **public key mismatch** (see Troubleshooting).
- Server replies but client never logs the final `TCP→UDP` → response is getting lost on the way back.

---

## Security

- **Authentication**: HMAC-SHA256 over a per-user secret + timestamp. Token window is ±5 minutes (replay protection).
- **Transport**: TLS 1.2+ with `HIGH:!aNULL:!MD5:!RC4` cipher list.
- **MITM protection**: set `ca_cert: ca.crt` in client config and the client will verify the server's certificate chain.
- **Secrets**: never stored in the tunnel frames; only used to derive the auth token.

---

## Troubleshooting

**`wg-quick: '/etc/wireguard/wg0.conf' does not exist`**
WireGuard hasn't been configured on this machine yet — see "Set up WireGuard" under Server setup (or "Create your WireGuard config" under Client setup).

**WireGuard log shows `Sending handshake initiation... did not complete after 5 seconds, retrying`, forever**
The handshake packet isn't getting a response. Run `wg show` on the VPS — confirm `wg0` is up, listening on the right port, and has a `peer:` entry. Then verify the keys actually match (a swapped/mistyped key causes WireGuard to silently drop unrecognized peers — no error, just silence):
```bash
# VPS's configured peer (the client) — should match client_public.key
grep -A1 '\[Peer\]' /etc/wireguard/wg0.conf | grep PublicKey
cat /etc/wireguard/keys/client_public.key

# Compare this against the Windows/client wg0.conf's [Peer] PublicKey
cat /etc/wireguard/keys/server_public.key
```
If you fix a key, reload without a full restart:
```bash
wg-quick down wg0 && wg-quick up wg0
```

**WireGuard says "connected" but no traffic flows / can't open any websites**
"Connected" only means the adapter and routes are configured — not that the handshake succeeded. Check the WireGuard log for handshake retries (above), and run `wg show` to confirm `latest handshake` is recent, not "(none)".

**Activating WireGuard disconnects `client.py` / kills the tunnel**
This is the full-tunnel routing self-reference problem — see "Fix full-tunnel routing" under Client setup. You need the `/32` exception route for your VPS's real IP.

**`[Errno 98] Address already in use` on client**
WireGuard is already listening on port 51820. Stop WireGuard first, then start `client.py`, then bring WireGuard back up.

**Authentication failed**
Confirm the `secret` in `client_config.yaml` matches the entry in `users.yaml` exactly, including case. Regenerate with `python server.py --add-user <name>` if unsure.

**Speed much lower than expected**
See "Performance tuning" above — try BBR + initcwnd first, then the AES-NI check if the ceiling persists.

**Debug logging**
See the "Debug logging" section above for per-hop packet tracing.

---

## File overview

```
smtp-wg-tunnel/
├── common.py            Shared: auth tokens, frame codec, socket tuning
├── server.py            VPS daemon — STARTTLS + WireGuard UDP bridge
├── client.py            Local daemon — SMTP client + WireGuard UDP proxy
├── generate_certs.py    One-shot TLS cert generator (wraps openssl CLI)
├── server_config.yaml   Server configuration template
├── client_config.yaml   Client configuration template
├── users.yaml           User/secret database template
└── requirements.txt     pip deps (just PyYAML)
```
