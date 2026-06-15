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
	udp  *net.UDPConn // bound once in Run(), reused across reconnects
	stop chan struct{}
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{cfg: cfg, stop: make(chan struct{})}
}

func (c *Client) Stop() {
	close(c.stop)
}

func (c *Client) Run() {
	cfg := c.cfg

	// Bind the local UDP socket once. WireGuard points its Endpoint here.
	// The socket persists across TLS reconnections so WireGuard doesn't
	// need to restart when the tunnel drops.
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

// connect performs the full SMTP STARTTLS handshake and returns a live TLS
// connection plus a buffered reader that MUST be used for all subsequent reads.
// The buffered reader may contain tunnel bytes already read from the TLS stream
// during the post-handshake SMTP exchange — discarding it would lose those bytes.
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

	// readLine reads one CRLF-terminated line directly from raw conn,
	// one byte at a time, to avoid buffering across the TLS upgrade.
	readLine := func(timeout time.Duration) (string, error) {
		return readLineRaw(raw, timeout)
	}
	drainSMTP := func() error {
		return drainRaw(raw, 30*time.Second)
	}

	// ── Phase 1: Pre-TLS SMTP ──────────────────────────────────────────────
	greeting, err := readLine(30 * time.Second)
	if err != nil || !strings.HasPrefix(greeting, "220") {
		raw.Close()
		return nil, nil, fmt.Errorf("greeting: %q %v", greeting, err)
	}
	raw.Write([]byte("EHLO client.local\r\n"))
	if err := drainSMTP(); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("EHLO: %w", err)
	}
	raw.Write([]byte("STARTTLS\r\n"))
	resp, err := readLine(30 * time.Second)
	if err != nil || !strings.HasPrefix(resp, "220") {
		raw.Close()
		return nil, nil, fmt.Errorf("STARTTLS: %q %v", resp, err)
	}

	// ── Phase 2: TLS upgrade ────────────────────────────────────────────────
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

	// Create the buffered reader HERE. Every subsequent read must go
	// through this reader to avoid losing bytes buffered from TLS.
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

	// ── Phase 3: Post-TLS SMTP ──────────────────────────────────────────────
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

	// wgPeer: the WireGuard kernel's source address.
	// Set atomically by the upload goroutine, read by the download goroutine.
	// atomic.Pointer[T] is safe without a mutex for pointer-sized updates.
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

	// writeMu serialises concurrent TLS writes (upload data + keepalives)
	var writeMu sync.Mutex
	tlsWrite := func(b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_, err := tlsConn.Write(b)
		return err
	}

	errCh := make(chan error, 2)

	// ── Upload goroutine: WireGuard → TLS ──────────────────────────────────
	// Reads WireGuard datagrams from the shared UDP socket, prepends the
	// 2-byte length header in-place (no extra allocation), and sends via TLS.
	// ReadFromUDP blocks until a packet arrives; a 20 s deadline triggers
	// a keepalive write if no traffic flows (holds the NAT mapping open).
	go func() {
		frame := make([]byte, frameHdrSize+maxPacketSize) // reused every iteration
		pkt := frame[frameHdrSize:]
		for {
			c.udp.SetReadDeadline(time.Now().Add(20 * time.Second))
			n, addr, err := c.udp.ReadFromUDP(pkt)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if e2 := tlsWrite(keepaliveFrame); e2 != nil {
						errCh <- e2
						return
					}
					continue
				}
				errCh <- err
				return
			}
			wgPeer.Store(addr)
			atomic.AddInt64(&ulB, int64(n))
			atomic.AddInt64(&ulP, 1)
			writeFrame(frame, n)
			if err := tlsWrite(frame[:frameHdrSize+n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// ── Download goroutine: TLS → WireGuard ────────────────────────────────
	// Reads length-prefixed frames from the buffered TLS reader and sends
	// raw WireGuard datagrams back to the WireGuard kernel via UDP.
	// Must use br (not tlsConn directly) — br may contain bytes buffered
	// during the post-handshake SMTP exchange.
	go func() {
		hdr := make([]byte, frameHdrSize)
		buf := make([]byte, maxPacketSize)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				errCh <- err
				return
			}
			n := readFrameLen(hdr)
			if n == 0 {
				continue // keepalive — discard
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

	// Wait for first goroutine to stop
	if err := <-errCh; err != nil && err != io.EOF &&
		!strings.Contains(err.Error(), "use of closed") {
		log.Printf("Tunnel: %v", err)
	}

	// Tear down:
	// - Close tlsConn → unblocks io.ReadFull in download goroutine
	// - Set immediate UDP deadline → unblocks ReadFromUDP in upload goroutine
	//   (do NOT close c.udp — it's shared across reconnects)
	tlsConn.Close()
	c.udp.SetReadDeadline(time.Now())
	<-errCh                            // drain second goroutine
	c.udp.SetReadDeadline(time.Time{}) // clear deadline for next session
}
