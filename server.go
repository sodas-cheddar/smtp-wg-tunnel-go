package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── TLS context ────────────────────────────────────────────────────────────────

func buildServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}, nil
}

// ── Server ─────────────────────────────────────────────────────────────────────

type Server struct {
	cfg    *ServerConfig
	users  Users
	tlsCfg *tls.Config
}

func NewServer(cfg *ServerConfig, users Users) *Server {
	return &Server{cfg: cfg, users: users}
}

func (s *Server) Run() {
	tlsCfg, err := buildServerTLSConfig(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		log.Fatalf("TLS config: %v", err)
	}
	s.tlsCfg = tlsCfg

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen %s: %v", addr, err)
	}
	defer ln.Close()

	log.Printf("Listening on %s (SMTP/STARTTLS disguise)", addr)
	log.Printf("WireGuard target: %s:%d", s.cfg.WGHost, s.cfg.WGPort)
	log.Printf("SMTP hostname: %s  |  users: %d", s.cfg.Hostname, len(s.users))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed") {
				log.Printf("Accept: %v", err)
			}
			return
		}
		go s.handleConn(conn)
	}
}

// ── Per-connection session ─────────────────────────────────────────────────────

type serverSession struct {
	raw     net.Conn
	tlsConn *tls.Conn
	br      *bufio.Reader
	peer    string
	user    string
	srv     *Server
}

func (s *Server) handleConn(raw net.Conn) {
	peer := raw.RemoteAddr().String()
	sess := &serverSession{raw: raw, peer: peer, srv: s}
	defer func() {
		raw.Close()
		log.Printf("%s: disconnected (user=%s)", peer, sess.user)
	}()
	log.Printf("%s: connected", peer)

	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(4 * 1024 * 1024)
		tc.SetWriteBuffer(4 * 1024 * 1024)
	}
	if err := sess.preHandshake(); err != nil {
		log.Printf("%s: pre-TLS: %v", peer, err)
		return
	}
	if err := sess.upgradeTLS(); err != nil {
		log.Printf("%s: TLS: %v", peer, err)
		return
	}
	if err := sess.postHandshake(); err != nil {
		log.Printf("%s: auth: %v", peer, err)
		return
	}
	sess.runTunnel()
}

// ── SMTP helpers ───────────────────────────────────────────────────────────────

func readLineRaw(conn net.Conn, timeout time.Duration) (string, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})
	var buf []byte
	b := [1]byte{}
	for {
		if _, err := conn.Read(b[:]); err != nil {
			return "", err
		}
		buf = append(buf, b[0])
		n := len(buf)
		if n >= 2 && buf[n-2] == '\r' && buf[n-1] == '\n' {
			return strings.TrimRight(string(buf), "\r\n"), nil
		}
	}
}

func drainRaw(conn net.Conn) error {
	for {
		line, err := readLineRaw(conn, 30*time.Second)
		if err != nil {
			return err
		}
		if len(line) < 4 || line[3] == ' ' {
			return nil
		}
	}
}

func (sess *serverSession) writeTLS(s string) { sess.tlsConn.Write([]byte(s)) }

func (sess *serverSession) readTLSLine() (string, error) {
	sess.tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := sess.br.ReadString('\n')
	sess.tlsConn.SetDeadline(time.Time{})
	return strings.TrimRight(line, "\r\n"), err
}

func (sess *serverSession) drainTLS() error {
	for {
		line, err := sess.readTLSLine()
		if err != nil {
			return err
		}
		if len(line) < 4 || line[3] == ' ' {
			return nil
		}
	}
}

// ── SMTP handshake ─────────────────────────────────────────────────────────────

func (sess *serverSession) preHandshake() error {
	h := sess.srv.cfg.Hostname
	sess.raw.Write([]byte(fmt.Sprintf("220 %s ESMTP Postfix (Ubuntu)\r\n", h)))

	line, err := readLineRaw(sess.raw, 30*time.Second)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
		return fmt.Errorf("expected EHLO, got %q", line)
	}
	sess.raw.Write([]byte(fmt.Sprintf(
		"250-%s\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 DSN\r\n", h)))

	line, err = readLineRaw(sess.raw, 30*time.Second)
	if err != nil {
		return err
	}
	if strings.ToUpper(line) != "STARTTLS" {
		return fmt.Errorf("expected STARTTLS, got %q", line)
	}
	sess.raw.Write([]byte("220 2.0.0 Ready to start TLS\r\n"))
	return nil
}

func (sess *serverSession) upgradeTLS() error {
	tc := tls.Server(sess.raw, sess.srv.tlsCfg)
	tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		return err
	}
	tc.SetDeadline(time.Time{})
	sess.tlsConn = tc
	sess.br = bufio.NewReaderSize(tc, 2*1024*1024)
	return nil
}

func (sess *serverSession) postHandshake() error {
	h := sess.srv.cfg.Hostname
	line, err := sess.readTLSLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
		return fmt.Errorf("expected EHLO, got %q", line)
	}
	sess.writeTLS(fmt.Sprintf("250-%s\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 DSN\r\n", h))

	line, err = sess.readTLSLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(line), "AUTH PLAIN") {
		sess.writeTLS("503 5.5.1 Error: send AUTH PLAIN\r\n")
		return fmt.Errorf("expected AUTH PLAIN, got %q", line)
	}
	parts := strings.SplitN(line, " ", 3)
	var tokenB64 string
	if len(parts) >= 3 {
		tokenB64 = strings.TrimSpace(parts[2])
	} else {
		sess.writeTLS("334 \r\n")
		if tokenB64, err = sess.readTLSLine(); err != nil {
			return err
		}
	}

	username := getUsernameFromToken(tokenB64)
	secret, ok := sess.srv.users[username]
	if !ok || !verifyToken(secret, tokenB64) {
		sess.writeTLS("535 5.7.8 Authentication credentials invalid\r\n")
		return fmt.Errorf("auth failed for %q", username)
	}
	sess.user = username
	sess.writeTLS("235 2.7.0 Authentication successful\r\n")

	if line, err = sess.readTLSLine(); err != nil {
		return err
	}
	if strings.ToUpper(line) != "WGTUNNEL" {
		sess.writeTLS("500 5.5.1 Command not recognized\r\n")
		return fmt.Errorf("expected WGTUNNEL, got %q", line)
	}
	sess.writeTLS("299 WireGuard tunnel mode activated\r\n")
	log.Printf("%s: user %q authenticated — tunnel active", sess.peer, username)
	return nil
}

// ── Tunnel ─────────────────────────────────────────────────────────────────────

func (sess *serverSession) runTunnel() {
	cfg := sess.srv.cfg
	wgAddr := &net.UDPAddr{IP: net.ParseIP(cfg.WGHost), Port: cfg.WGPort}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Printf("%s: UDP: %v", sess.peer, err)
		return
	}
	udp.SetReadBuffer(4 * 1024 * 1024)
	udp.SetWriteBuffer(4 * 1024 * 1024)

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
				log.Printf("%s: stats  ul=%.1f Mbps  dl=%.1f Mbps  wg_pps=%.0f",
					sess.peer,
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

	// ── Download: WireGuard → TLS (batched) ────────────────────────────────
	//
	// THE CORE FIX: every individual tlsConn.Write() call has a fixed
	// per-call overhead (~116 µs on Linux, ~440 µs on Windows). Sending one
	// packet per write caps throughput at ~8,620 pps (Linux) / ~2,272 pps
	// (Windows). By batching packets accumulated over a 1 ms window into a
	// single write we stay well below the per-call budget while still
	// matching the WireGuard packet rate needed for 150 Mbps.
	//
	// Stage 1 (reader goroutine): blocking ReadFrom — no deadline, no per-
	// packet overhead. Feeds a buffered channel so it is never blocked by
	// the TLS sender.
	//
	// Stage 2 (sender goroutine): drains the channel every millisecond
	// (or when the batch hits 48 KB) and sends everything in one Write.

	pktChDL := make(chan []byte, 1024)

	wg.Add(1)
	go func() { // Stage 1: UDP reader
		defer wg.Done()
		defer close(pktChDL)
		buf := make([]byte, maxPacketSize)
		for {
			n, _, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			atomic.AddInt64(&dlB, int64(n))
			select {
			case pktChDL <- pkt:
			default: // channel full: drop (relief valve, not the normal path)
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
			if _, err := sess.tlsConn.Write(batch); err != nil {
				errCh <- err
				return false
			}
			batch = batch[:0]
			lastSent = time.Now()
			return true
		}

		for {
			select {
			case pkt, ok := <-pktChDL:
				if !ok {
					flush()
					return
				}
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
					sess.tlsConn.Write(keepaliveFrame)
					lastSent = time.Now()
				}
			}
		}
	}()

	// ── Upload: TLS → WireGuard ─────────────────────────────────────────────
	// Reads length-prefixed frames from the buffered TLS reader and sends
	// individual UDP datagrams to wg0. No batching needed here: the OS
	// kernel handles UDP sends efficiently with minimal per-call overhead.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hdr := make([]byte, frameHdrSize)
		buf := make([]byte, maxPacketSize)
		for {
			if _, err := io.ReadFull(sess.br, hdr); err != nil {
				errCh <- err
				return
			}
			n := readFrameLen(hdr)
			if n == 0 {
				continue // keepalive
			}
			if _, err := io.ReadFull(sess.br, buf[:n]); err != nil {
				errCh <- err
				return
			}
			atomic.AddInt64(&ulB, int64(n))
			atomic.AddInt64(&ulP, 1)
			udp.WriteTo(buf[:n], wgAddr)
		}
	}()

	// Wait for first error, then tear everything down
	if err = <-errCh; err != nil && err != io.EOF &&
		!strings.Contains(err.Error(), "use of closed") {
		log.Printf("%s: tunnel: %v", sess.peer, err)
	}
	sess.tlsConn.Close()
	udp.Close() // unblocks ReadFrom in the UDP reader goroutine
	wg.Wait()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
