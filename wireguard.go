package main

// wireguard.go — embedded WireGuard client using wireguard-go.
//
// Instead of relying on WireGuard-Windows (wireguard-nt or TunSafe), which
// register Windows Filtering Platform callouts that add ~430 µs overhead per
// outgoing UDP packet (capping upload at ~2,300 pps = 25 Mbps), our binary
// runs wireguard-go in-process with a custom conn.Bind that routes all
// WireGuard traffic through our SMTP tunnel instead of real UDP.
//
// Packet flow:
//
//   App → OS TUN/wintun → wireguard-go encrypt → tunnelBind.Send() → SMTP TLS → VPS wg0 → internet
//   App ← OS TUN/wintun ← wireguard-go decrypt ← tunnelBind.recv  ← SMTP TLS ← VPS wg0 ← internet
//
// The server side is UNCHANGED — it still forwards WireGuard frames via UDP
// to the VPS's local wg0.
//
// No WireGuard-Windows app needed. Run:
//   smtp-wg-tunnel.exe client -c client_config.yaml --wg wg0.conf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"bytes"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// ── WireGuard config parsing ───────────────────────────────────────────────────
// Parses the standard wg0.conf INI format.

type WGConfig struct {
	PrivateKey string   // base64
	Addresses  []string // e.g. ["10.0.0.2/32"]
	DNS        []string
	MTU        int
	Peers      []WGPeer
}

type WGPeer struct {
	PublicKey           string
	AllowedIPs         []string
	Endpoint            string // original endpoint (ignored — we use SMTP tunnel)
	PersistentKeepalive int
}

func parseWGConfig(path string) (*WGConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &WGConfig{MTU: 1420}
	var inIface, inPeer bool
	var cur WGPeer

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case "[Interface]":
			if cur.PublicKey != "" {
				cfg.Peers = append(cfg.Peers, cur)
				cur = WGPeer{}
			}
			inIface, inPeer = true, false
			continue
		case "[Peer]":
			if cur.PublicKey != "" {
				cfg.Peers = append(cfg.Peers, cur)
			}
			cur = WGPeer{}
			inIface, inPeer = false, true
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if ci := strings.Index(v, " #"); ci >= 0 {
			v = strings.TrimSpace(v[:ci])
		}
		if inIface {
			switch k {
			case "PrivateKey":
				cfg.PrivateKey = v
			case "Address":
				for _, a := range strings.Split(v, ",") {
					cfg.Addresses = append(cfg.Addresses, strings.TrimSpace(a))
				}
			case "DNS":
				for _, d := range strings.Split(v, ",") {
					cfg.DNS = append(cfg.DNS, strings.TrimSpace(d))
				}
			case "MTU":
				if m, err := strconv.Atoi(v); err == nil {
					cfg.MTU = m
				}
			}
		} else if inPeer {
			switch k {
			case "PublicKey":
				cur.PublicKey = v
			case "AllowedIPs":
				for _, a := range strings.Split(v, ",") {
					cur.AllowedIPs = append(cur.AllowedIPs, strings.TrimSpace(a))
				}
			case "Endpoint":
				cur.Endpoint = v
			case "PersistentKeepalive":
				if n, err := strconv.Atoi(v); err == nil {
					cur.PersistentKeepalive = n
				}
			}
		}
	}
	if cur.PublicKey != "" {
		cfg.Peers = append(cfg.Peers, cur)
	}
	return cfg, sc.Err()
}

func b64ToHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ── Custom conn.Bind — routes WireGuard over our SMTP tunnel ───────────────────
//
// wireguard-go calls Send() to emit encrypted WireGuard frames.
// Our tunnel goroutines call deliver() to push received frames in.

type tunnelBind struct {
	outCh chan []byte  // wireguard-go → SMTP sender goroutine
	inCh  chan []byte  // SMTP receiver goroutine → wireguard-go
	done  chan struct{}
	mu    sync.Mutex
	dead  bool
}

func newTunnelBind() *tunnelBind {
	return &tunnelBind{
		outCh: make(chan []byte, 1024),
		inCh:  make(chan []byte, 1024),
		done:  make(chan struct{}),
	}
}

// deliver pushes a received WireGuard packet to wireguard-go.
func (b *tunnelBind) deliver(pkt []byte) {
	p := make([]byte, len(pkt))
	copy(p, pkt)
	select {
	case b.inCh <- p:
	default: // drop if wireguard-go is not consuming fast enough
	}
}

// resetDone recreates the done channel for a fresh session (called after reconnect).
// outCh/inCh are kept — wireguard-go keeps queuing/reading across reconnects.
func (b *tunnelBind) resetDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dead {
		b.done = make(chan struct{})
		b.dead = false
	}
}

// closeDone signals the current SMTP session ended. wireguard-go's
// ReceiveFunc will unblock and return ErrClosed, allowing a new session.
func (b *tunnelBind) closeDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.dead {
		b.dead = true
		close(b.done)
	}
}

// ── conn.Bind interface ────────────────────────────────────────────────────────

func (b *tunnelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.resetDone()
	rf := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-b.inCh:
			n := copy(bufs[0], pkt)
			sizes[0] = n
			eps[0] = &wgEndpoint{}
			return 1, nil
		case <-b.done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{rf}, 0, nil
}

func (b *tunnelBind) Close() error {
	b.closeDone()
	return nil
}

func (b *tunnelBind) SetMark(mark uint32) error { return nil }

func (b *tunnelBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := make([]byte, len(buf))
		copy(pkt, buf)
		select {
		case b.outCh <- pkt:
		default: // drop if sender is blocked; WireGuard handles retransmits
		}
	}
	return nil
}

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &wgEndpoint{addr: s}, nil
}

func (b *tunnelBind) BatchSize() int { return 1 }

// ── conn.Endpoint (minimal — we use a single SMTP tunnel, not UDP) ─────────────

type wgEndpoint struct{ addr string }

func (e *wgEndpoint) ClearSrc()           {}
func (e *wgEndpoint) SrcToString() string  { return "" }
func (e *wgEndpoint) DstToString() string  { return e.addr }
func (e *wgEndpoint) DstToBytes() []byte   { return []byte(e.addr) }
func (e *wgEndpoint) DstIP() netip.Addr    { return netip.Addr{} }
func (e *wgEndpoint) SrcIP() netip.Addr    { return netip.Addr{} }

// ── TUN interface setup ────────────────────────────────────────────────────────

func createAndConfigureTUN(cfg *WGConfig, serverHost string) (tun.Device, error) {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	log.Printf("Creating TUN interface (MTU %d)…", mtu)
	tunDev, err := tun.CreateTUN("wg0", mtu)
	if err != nil {
		return nil, fmt.Errorf("tun.CreateTUN: %w\n"+
			"  On Windows, wintun.dll must be in the same directory or System32.\n"+
			"  Download from https://wintun.net/ or reinstall WireGuard-Windows.", err)
	}

	name, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, err
	}
	log.Printf("TUN interface ready: %s", name)

	// Add a bypass route for the SMTP server so it doesn't loop through TUN
	if serverHost != "" {
		if gw, err := defaultGateway(); err == nil {
			_ = addBypassRoute(serverHost, gw) // best-effort
		}
	}

	if err := applyTUNConfig(name, cfg); err != nil {
		log.Printf("Warning: TUN config incomplete: %v", err)
		log.Printf("Run manually: ip addr add <addr> dev %s && ip link set %s up", name, name)
	}

	return tunDev, nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}

func defaultGateway() (string, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return "", err
		}
		// format: "default via GW dev DEV …"
		parts := strings.Fields(string(out))
		for i, p := range parts {
			if p == "via" && i+1 < len(parts) {
				return parts[i+1], nil
			}
		}
		return "", fmt.Errorf("no default gateway found")

	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop`,
		).Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil

	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "gateway:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					return parts[len(parts)-1], nil
				}
			}
		}
		return "", fmt.Errorf("no gateway in route output")
	}
	return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func addBypassRoute(host, gw string) error {
	switch runtime.GOOS {
	case "linux":
		return run("ip", "route", "add", host+"/32", "via", gw)
	case "windows":
		return run("route", "add", host, "mask", "255.255.255.255", gw)
	case "darwin":
		return run("route", "add", "-host", host, gw)
	}
	return nil
}

func applyTUNConfig(iface string, cfg *WGConfig) error {
	switch runtime.GOOS {
	case "linux":
		for _, addr := range cfg.Addresses {
			if err := run("ip", "address", "add", addr, "dev", iface); err != nil {
				return err
			}
		}
		if err := run("ip", "link", "set", iface, "up"); err != nil {
			return err
		}
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				run("ip", "route", "add", aip, "dev", iface) //nolint
			}
		}

	case "windows":
		time.Sleep(500 * time.Millisecond) // wait for interface to appear in netsh
		for _, addr := range cfg.Addresses {
			run("netsh", "interface", "ip", "add", "address", iface, addr) //nolint
		}
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				run("route", "add", aip, iface) //nolint
			}
		}

	case "darwin":
		for _, addr := range cfg.Addresses {
			ip, _, _ := net.ParseCIDR(addr)
			if ip != nil {
				run("ifconfig", iface, ip.String(), ip.String(), "alias") //nolint
			}
		}
		run("ifconfig", iface, "up") //nolint
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				run("route", "add", "-net", aip, "-interface", iface) //nolint
			}
		}
	}

	if len(cfg.DNS) > 0 {
		log.Printf("DNS servers (%s) — configure manually or via your OS resolver", strings.Join(cfg.DNS, ", "))
	}
	return nil
}

// ── wireguard-go device ────────────────────────────────────────────────────────

func newWireGuardDevice(tunDev tun.Device, bind *tunnelBind, cfg *WGConfig, serverAddr string) (*device.Device, error) {
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { log.Printf("[wg] "+format, args...) },
		Errorf:   func(format string, args ...any) { log.Printf("[wg ERR] "+format, args...) },
	}

	dev := device.NewDevice(tunDev, bind, logger)

	privHex, err := b64ToHex(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\nlisten_port=0\n", privHex)

	for _, peer := range cfg.Peers {
		pubHex, err := b64ToHex(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer public key: %w", err)
		}
		// The endpoint must be a host:port so wireguard-go can associate
		// responses with this peer. We use a dummy port since our bind
		// ignores the UDP address entirely.
		ep := serverAddr
		if ep == "" {
			ep = "0.0.0.0:51820"
		}
		fmt.Fprintf(&sb, "public_key=%s\nendpoint=%s\n", pubHex, ep)
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
		fmt.Fprintf(&sb, "replace_allowed_ips=true\n")
		for _, aip := range peer.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", aip)
		}
		fmt.Fprintln(&sb)
	}

	if err := dev.IpcSet(sb.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard IPC: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard Up: %w", err)
	}
	log.Println("wireguard-go device up")
	return dev, nil
}
