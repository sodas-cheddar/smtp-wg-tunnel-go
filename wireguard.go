package main

// wireguard.go — embedded WireGuard client using wireguard-go.
//
// Eliminates the Windows Filtering Platform (WFP) callout overhead (~430 µs per
// packet) that caps WireGuard-Windows upload at ~2,300 pps = 25 Mbps.
// wireguard-go runs in-process with no kernel driver and no WFP hooks.
//
// Transport design
// ─────────────────
// wireguard-go normally sends encrypted WireGuard frames over UDP.
// Here we replace UDP with our SMTP tunnel via tunnelBind (conn.Bind):
//
//   App → TUN → wireguard-go encrypt → tunnelBind.Send() → outCh ──────→ SMTP TLS → VPS wg0 → internet
//   App ← TUN ← wireguard-go decrypt ← tunnelBind.ReceiveFunc ← inCh ← SMTP TLS ← VPS wg0 ← internet
//
// Key design rule: closeCh is ONLY closed when the WireGuard DEVICE shuts down.
// Per-SMTP-session coordination uses a local sessionCh in runTunnelWG so that
// wireguard-go's ReceiveFunc goroutine survives across reconnects.

import (
	"bufio"
	"bytes"
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
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// ── WireGuard config ───────────────────────────────────────────────────────────

type WGConfig struct {
	PrivateKey string
	Addresses  []string
	DNS        []string
	MTU        int
	Peers      []WGPeer
}

type WGPeer struct {
	PublicKey           string
	AllowedIPs          []string
	Endpoint            string
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

// ── tunnelBind ─────────────────────────────────────────────────────────────────
//
// Implements conn.Bind. wireguard-go calls Send() to emit frames; our
// SMTP goroutines call deliver() to push received frames in.
//
// Lifetime rules:
//   • outCh / inCh persist for the life of the process.
//   • closeCh is closed ONLY when the WireGuard device is shut down (dev.Close).
//     Do NOT close it on SMTP session disconnect — that would permanently kill
//     wireguard-go's ReceiveFunc goroutine and break all subsequent reconnects.
//   • Per-SMTP-session teardown is handled by a local sessionCh in runTunnelWG.

type tunnelBind struct {
	outCh   chan []byte  // wireguard-go → SMTP upload goroutine
	inCh    chan []byte  // SMTP download goroutine → wireguard-go ReceiveFunc
	closeCh chan struct{} // closed only on device.Close()
	closeOnce sync.Once

	// debug counters
	sendCalls  int64 // times wireguard-go called Send()
	sendDrops  int64 // packets dropped because outCh was full
}

func newTunnelBind() *tunnelBind {
	return &tunnelBind{
		outCh:   make(chan []byte, 2048),
		inCh:    make(chan []byte, 2048),
		closeCh: make(chan struct{}),
	}
}

// deliver pushes a received WireGuard packet to wireguard-go's ReceiveFunc.
func (b *tunnelBind) deliver(pkt []byte) {
	p := make([]byte, len(pkt))
	copy(p, pkt)
	select {
	case b.inCh <- p:
	default:
		// wireguard-go isn't consuming fast enough — drop; WireGuard handles loss
	}
}

// ── conn.Bind ─────────────────────────────────────────────────────────────────

func (b *tunnelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	rf := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		// Block until wireguard-go delivers a packet from the SMTP tunnel, OR
		// until the WireGuard device itself closes. Do NOT block on any
		// per-session channel here — this goroutine must survive reconnects.
		select {
		case pkt := <-b.inCh:
			n := copy(bufs[0], pkt)
			sizes[0] = n
			eps[0] = &wgEndpoint{}
			return 1, nil
		case <-b.closeCh:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{rf}, 0, nil
}

func (b *tunnelBind) Close() error {
	// Called by device.Close() — signal the ReceiveFunc to exit.
	b.closeOnce.Do(func() { close(b.closeCh) })
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
		atomic.AddInt64(&b.sendCalls, 1)
		select {
		case b.outCh <- pkt:
		default:
			atomic.AddInt64(&b.sendDrops, 1)
		}
	}
	return nil
}

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &wgEndpoint{addr: s}, nil
}

func (b *tunnelBind) BatchSize() int { return 1 }

// ── conn.Endpoint ──────────────────────────────────────────────────────────────

type wgEndpoint struct{ addr string }

func (e *wgEndpoint) ClearSrc()          {}
func (e *wgEndpoint) SrcToString() string { return "" }
func (e *wgEndpoint) DstToString() string { return e.addr }
func (e *wgEndpoint) DstToBytes() []byte  { return []byte(e.addr) }
func (e *wgEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *wgEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// ── TUN creation + IP configuration ───────────────────────────────────────────

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
			"  Download: https://wintun.net/", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, err
	}
	log.Printf("TUN interface: %s", name)

	// Add bypass route for the SMTP server before AllowedIPs routes go in,
	// so our own connection doesn't get routed through the tunnel.
	if serverHost != "" {
		if gw, err := defaultGateway(); err == nil {
			if err := addBypassRoute(serverHost, gw); err != nil {
				log.Printf("Warning: bypass route for %s: %v (add manually if needed)", serverHost, err)
			} else {
				log.Printf("Bypass route added: %s via %s", serverHost, gw)
			}
		} else {
			log.Printf("Warning: could not detect default gateway: %v", err)
		}
	}

	if err := applyTUNConfig(name, cfg); err != nil {
		log.Printf("Warning: TUN config incomplete: %v", err)
	}
	return tunDev, nil
}

func runCmd(name string, args ...string) error {
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
		parts := strings.Fields(string(out))
		for i, p := range parts {
			if p == "via" && i+1 < len(parts) {
				return parts[i+1], nil
			}
		}
		return "", fmt.Errorf("no gateway in: %s", string(out))

	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			`(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Sort-Object RouteMetric|Select-Object -First 1).NextHop`,
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
		return "", fmt.Errorf("no gateway found")
	}
	return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func addBypassRoute(host, gw string) error {
	switch runtime.GOOS {
	case "linux":
		return runCmd("ip", "route", "add", host+"/32", "via", gw)
	case "windows":
		return runCmd("route", "add", host, "mask", "255.255.255.255", gw)
	case "darwin":
		return runCmd("route", "add", "-host", host, gw)
	}
	return nil
}

func applyTUNConfig(iface string, cfg *WGConfig) error {
	switch runtime.GOOS {
	case "linux":
		for _, addr := range cfg.Addresses {
			if err := runCmd("ip", "address", "add", addr, "dev", iface); err != nil {
				return err
			}
		}
		if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
			return err
		}
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				runCmd("ip", "route", "add", aip, "dev", iface) //nolint
			}
		}

	case "windows":
		time.Sleep(500 * time.Millisecond)
		for _, addr := range cfg.Addresses {
			runCmd("netsh", "interface", "ip", "add", "address", iface, addr) //nolint
		}
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				runCmd("route", "add", aip, iface) //nolint
			}
		}

	case "darwin":
		for _, addr := range cfg.Addresses {
			ip, _, _ := net.ParseCIDR(addr)
			if ip != nil {
				runCmd("ifconfig", iface, ip.String(), ip.String(), "alias") //nolint
			}
		}
		runCmd("ifconfig", iface, "up") //nolint
		for _, p := range cfg.Peers {
			for _, aip := range p.AllowedIPs {
				runCmd("route", "add", "-net", aip, "-interface", iface) //nolint
			}
		}
	}

	if len(cfg.DNS) > 0 {
		log.Printf("DNS %s — configure via your OS resolver (e.g. resolvconf, systemd-resolved, netsh)",
			strings.Join(cfg.DNS, ", "))
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
		// Endpoint is required by wireguard-go for peer routing, but our
		// tunnelBind.Send() ignores it — we have only one SMTP tunnel.
		// Use a dummy valid-looking host:port so wireguard-go doesn't reject it.
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
		return nil, fmt.Errorf("wireguard IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard Up: %w", err)
	}
	log.Println("wireguard-go device up — handshake will begin once SMTP tunnel connects")
	return dev, nil
}
