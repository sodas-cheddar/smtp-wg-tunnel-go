package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Client ─────────────────────────────────────────────────────────────────────

type Client struct {
	cfg  *ClientConfig
	udp  *net.UDPConn // bound once in Run(), shared across reconnects
	stop chan struct{}
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{cfg: cfg, stop: make(chan struct{})}
}

func (c *Client) Stop() { close(c.stop) }

func (c *Client) Run() {
	cfg := c.cfg

	udp, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(cfg.LocalWGHost),
		Port: cfg.LocalWGPort,
	})
	if err != nil {
		log.Fatalf("UDP bind %s:%d: %v", cfg.LocalWGHost, cfg.LocalWGPort, err)
	}
	defer udp.Close()
	udp.SetReadBuffer(4 * 1024 * 1024)
	udp.SetWriteBuffer(4 * 1024 * 1024)
	c.udp = udp

	log.Printf("WireGuard proxy on UDP %s:%d", cfg.LocalWGHost, cfg.LocalWGPort)
	log.Printf("WireGuard peer config:  Endpoint = %s:%d  |  MTU = 1380  |  PersistentKeepalive = 25",
		cfg.LocalWGHost, cfg.LocalWGPort)

	for {
		select {
		case <-c.stop:
			return
		default:
		}

		tlsConn, br, err := c.connect()
		if err != nil {
			log.Printf("Connection failed: %v", err)
		} else {
			c.runTunnel(tlsConn, br)
		}

		select {
		case <-c.stop:
			return
		case <-time.After(cfg.ReconnectDelay):
			log.Printf("Reconnecting in %v ...", cfg.ReconnectDelay)
		}
	}
}

// ── Handshake ──────────────────────────────────────────────────────────────────

func (c *Client) connect() (*tls.Conn, *bufio.Reader, error) {
	cfg := c.cfg
	addr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ServerPort)
	log.Printf("Connecting to %s ...", addr)

	raw, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP: %w", err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	greeting, err := readLineRaw(raw, 30*time.Second)
	if err != nil || !strings.HasPrefix(greeting, "220") {
		raw.Close()
		return nil, nil, fmt.Errorf("greeting: %q %v", greeting, err)
	}

	raw.Write([]byte("EHLO client.local\r\n"))
	if err := drainRaw(raw); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("EHLO: %w", err)
	}

	raw.Write([]byte("STARTTLS\r\n"))
	resp, err := readLineRaw(raw, 30*time.Second)
	if err != nil || !strings.HasPrefix(resp, "220") {
		raw.Close()
		return nil, nil, fmt.Errorf("STARTTLS: %q %v", resp, err)
	}

	// TLS upgrade
	tlsCfg, err := c.buildTLSConfig()
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	tlsConn := tls.Client(raw, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("TLS handshake: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})

	// All subsequent reads go through this buffer — it may contain tunnel
	// bytes buffered during the post-handshake SMTP exchange
	br := bufio.NewReaderSize(tlsConn, 2*1024*1024)

	readTLSLine := func() (string, error) {
		tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := br.ReadString('\n')
		tlsConn.SetDeadline(time.Time{})
		return strings.TrimRight(line, "\r\n"), err
	}
	drainTLS := func() error {
		for {
			line, err := readTLSLine()
			if err != nil {
				return err
			}
			if len(line) < 4 || line[3] == ' ' {
				return nil
			}
		}
	}

	tlsConn.Write([]byte("EHLO client.local\r\n"))
	if err := drainTLS(); err != nil {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("post-TLS EHLO: %w", err)
	}

	token := createToken(cfg.Secret, cfg.Username)
	tlsConn.Write([]byte("AUTH PLAIN " + token + "\r\n"))
	if resp, err = readTLSLine(); err != nil || !strings.HasPrefix(resp, "235") {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("auth: %q %v", resp, err)
	}

	tlsConn.Write([]byte("WGTUNNEL\r\n"))
	if resp, err = readTLSLine(); err != nil || !strings.HasPrefix(resp, "299") {
		tlsConn.Close()
		return nil, nil, fmt.Errorf("WGTUNNEL: %q %v", resp, err)
	}

	log.Println("✓ Tunnel established — WireGuard mode active")
	return tlsConn, br, nil
}

func (c *Client) buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: c.cfg.ServerHost,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	if c.cfg.CACert != "" {
		pem, err := os.ReadFile(c.cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert: failed to parse PEM")
		}
		cfg.RootCAs = pool
	} else {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// ── Tunnel ─────────────────────────────────────────────────────────────────────

func (c *Client) runTunnel(tlsConn *tls.Conn, br *bufio.Reader) {
	defer tlsConn.Close()

	var wgPeer atomic.Pointer[net.UDPAddr]

	// Stats
	var ulB, dlB, ulP int64
	t0 := time.Now()
	statsDone := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				e := time.Since(t0).Seconds()
				log.Printf("stats  ul=%.1f Mbps  dl=%.1f Mbps  wg_pps=%.0f",
					float64(atomic.SwapInt64(&ulB, 0))*8/e/1e6,
					float64(atomic.SwapInt64(&dlB, 0))*8/e/1e6,
					float64(atomic.SwapInt64(&ulP, 0))/e)
				t0 = time.Now()
			case <-statsDone:
				return
			}
		}
	}()
	defer close(statsDone)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	// ── Upload: WireGuard → TLS (batched) ──────────────────────────────────
	//
	// THE CORE FIX: per-tlsConn.Write() overhead is ~440 µs on Windows,
	// capping single-packet sends at ~2,272 pps = 25 Mbps. Batching all
	// packets accumulated over a 1 ms window into one Write reduces the
	// call rate to ~1,000/sec, well within budget for 150 Mbps.
	//
	// Stage 1 (reader): pure blocking ReadFromUDP — no deadline, no per-
	// packet overhead. Feeds a deep channel so it is never stalled by the
	// TLS sender.
	//
	// Stage 2 (sender): drains the channel every millisecond (or when the
	// batch reaches 48 KB) and issues a single tlsConn.Write per interval.
	// Keepalives are sent from within this goroutine so no write mutex
	// is needed — only one goroutine ever writes to tlsConn.

	pktChUL := make(chan []byte, 1024)

	wg.Add(1)
	go func() { // Stage 1: UDP reader (no deadline — blocks until packet or socket closed)
		defer wg.Done()
		defer close(pktChUL)
		buf := make([]byte, maxPacketSize)
		for {
			n, addr, err := c.udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wgPeer.Store(addr)
			atomic.AddInt64(&ulP, 1)
			atomic.AddInt64(&ulB, int64(n))
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case pktChUL <- pkt:
			default: // channel full: drop packet rather than stall the reader
			}
		}
	}()

	wg.Add(1)
	go func() { // Stage 2: batch TLS sender
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		batch := make([]byte, 0, 64*1024)
		var hdr [frameHdrSize]byte
		lastSent := time.Now()

		flush := func() bool {
			if len(batch) == 0 {
				return true
			}
			if _, err := tlsConn.Write(batch); err != nil {
				errCh <- err
				return false
			}
			batch = batch[:0]
			lastSent = time.Now()
			return true
		}

		for {
			select {
			case pkt, ok := <-pktChUL:
				if !ok { // reader closed: flush and exit
					flush()
					return
				}
				writeFrame(hdr[:], len(pkt))
				batch = append(batch, hdr[:]...)
				batch = append(batch, pkt...)
				if len(batch) >= 48*1024 { // eager flush at 48 KB
					if !flush() {
						return
					}
				}
			case <-ticker.C:
				if !flush() {
					return
				}
				// Keepalive: hold the TLS connection and NAT mapping open
				if time.Since(lastSent) > 19*time.Second {
					if _, err := tlsConn.Write(keepaliveFrame); err != nil {
						errCh <- err
						return
					}
					lastSent = time.Now()
				}
			}
		}
	}()

	// ── Download: TLS → WireGuard ───────────────────────────────────────────
	// Reads length-prefixed frames from the buffered TLS reader and sends
	// individual UDP datagrams to WireGuard. UDP sends are cheap per-call
	// so no batching is needed here.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hdr := make([]byte, frameHdrSize)
		buf := make([]byte, maxPacketSize)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				errCh <- err
				return
			}
			n := readFrameLen(hdr)
			if n == 0 {
				continue // keepalive
			}
			if _, err := io.ReadFull(br, buf[:n]); err != nil {
				errCh <- err
				return
			}
			atomic.AddInt64(&dlB, int64(n))
			if peer := wgPeer.Load(); peer != nil {
				c.udp.WriteToUDP(buf[:n], peer)
			}
		}
	}()

	// Wait for first goroutine to report an error, then tear down all three
	if err := <-errCh; err != nil && err != io.EOF &&
		!strings.Contains(err.Error(), "use of closed") {
		log.Printf("Tunnel: %v", err)
	}
	tlsConn.Close() // unblocks TLS reader in download goroutine
	// Unblock Stage-1 UDP reader without closing the shared socket:
	// a past-due deadline causes ReadFromUDP to return immediately
	c.udp.SetReadDeadline(time.Now())
	wg.Wait()
	c.udp.SetReadDeadline(time.Time{}) // clear for next session
}

// ── WireGuard-go mode ──────────────────────────────────────────────────────────
//
// Runs when --wg flag is provided. wireguard-go IS the WireGuard implementation;
// no external WireGuard-Windows app or UDP loopback needed.
// The tunnelBind routes all WireGuard crypto frames through our SMTP tunnel.

func (c *Client) RunWGMode(wgCfg *WGConfig) {
	cfg := c.cfg

	// Create TUN + wireguard-go with our custom bind
	bind := newTunnelBind()
	serverAddr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ServerPort)

	tunDev, err := createAndConfigureTUN(wgCfg, cfg.ServerHost)
	if err != nil {
		log.Fatalf("TUN: %v", err)
	}

	dev, err := newWireGuardDevice(tunDev, bind, wgCfg, serverAddr)
	if err != nil {
		tunDev.Close()
		log.Fatalf("WireGuard device: %v", err)
	}
	defer dev.Close()

	log.Printf("Embedded WireGuard active — all traffic routes via SMTP tunnel to %s", serverAddr)
	log.Printf("No WireGuard-Windows app needed.")

	// Reconnect loop: SMTP tunnel reconnects transparently; wireguard-go
	// keeps its TUN and crypto state across reconnects.
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		tlsConn, br, err := c.connect()
		if err != nil {
			log.Printf("Connection failed: %v", err)
		} else {
			bind.resetDone() // fresh session signal for ReceiveFunc
			c.runTunnelWG(tlsConn, br, bind)
		}

		select {
		case <-c.stop:
			return
		case <-time.After(cfg.ReconnectDelay):
			log.Printf("Reconnecting in %v …", cfg.ReconnectDelay)
		}
	}
}

// runTunnelWG is the same as runTunnel but sources/sinks are the tunnelBind
// channels instead of a UDP socket.
//
// Upload: bind.outCh  ← wireguard-go → batch → TLS write
// Download: TLS read → decode frame → bind.deliver() → wireguard-go
func (c *Client) runTunnelWG(tlsConn *tls.Conn, br *bufio.Reader, bind *tunnelBind) {
	defer tlsConn.Close()

	var ulB, dlB, ulP int64
	t0 := time.Now()
	statsDone := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				e := time.Since(t0).Seconds()
				log.Printf("stats  ul=%.1f Mbps  dl=%.1f Mbps  wg_pps=%.0f",
					float64(atomic.SwapInt64(&ulB, 0))*8/e/1e6,
					float64(atomic.SwapInt64(&dlB, 0))*8/e/1e6,
					float64(atomic.SwapInt64(&ulP, 0))/e)
				t0 = time.Now()
			case <-statsDone:
				return
			}
		}
	}()
	defer close(statsDone)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	// ── Upload: wireguard-go → TLS (batched) ──────────────────────────────
	// wireguard-go calls bind.Send() → outCh. No WFP callouts, no loopback.
	// We apply the same 1 ms coalescing window as the UDP path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		batch := make([]byte, 0, 64*1024)
		var hdr [frameHdrSize]byte
		lastSent := time.Now()

		flush := func() bool {
			if len(batch) == 0 {
				return true
			}
			if _, err := tlsConn.Write(batch); err != nil {
				errCh <- err
				return false
			}
			batch = batch[:0]
			lastSent = time.Now()
			return true
		}

		for {
			select {
			case pkt, ok := <-bind.outCh:
				if !ok {
					flush()
					return
				}
				atomic.AddInt64(&ulP, 1)
				atomic.AddInt64(&ulB, int64(len(pkt)))
				writeFrame(hdr[:], len(pkt))
				batch = append(batch, hdr[:]...)
				batch = append(batch, pkt...)
				if len(batch) >= 48*1024 {
					if !flush() {
						return
					}
				}

			case <-ticker.C:
				if !flush() {
					return
				}
				if time.Since(lastSent) > 19*time.Second {
					if _, err := tlsConn.Write(keepaliveFrame); err != nil {
						errCh <- err
						return
					}
					lastSent = time.Now()
				}

			case <-bind.done:
				// SMTP session ended — stop this goroutine; wireguard-go
				// will queue outbound packets in outCh until reconnect.
				return
			}
		}
	}()

	// ── Download: TLS → wireguard-go ──────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		hdr := make([]byte, frameHdrSize)
		buf := make([]byte, maxPacketSize)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				errCh <- err
				return
			}
			n := readFrameLen(hdr)
			if n == 0 {
				continue // keepalive
			}
			if _, err := io.ReadFull(br, buf[:n]); err != nil {
				errCh <- err
				return
			}
			atomic.AddInt64(&dlB, int64(n))
			bind.deliver(buf[:n])
		}
	}()

	if err := <-errCh; err != nil && err != io.EOF &&
		!strings.Contains(err.Error(), "use of closed") {
		log.Printf("Tunnel: %v", err)
	}
	bind.closeDone()  // unblock upload goroutine's <-bind.done
	tlsConn.Close()  // unblock download goroutine's ReadFull
	wg.Wait()
}
