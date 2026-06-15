package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	frameHdrSize  = 2
	maxPacketSize = 65535
)

var keepaliveFrame = []byte{0, 0}

// ── Authentication ─────────────────────────────────────────────────────────────
// SASL PLAIN wire format: base64( \0 username \0 timestamp:HMAC-SHA256 )
// Token window ±5 min prevents replay attacks.

func createToken(secret, username string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("wgtunnel:" + ts))
	h := fmt.Sprintf("%x", mac.Sum(nil))
	raw := "\x00" + username + "\x00" + ts + ":" + h
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func getUsernameFromToken(tokenB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 || parts[0] != "" {
		return ""
	}
	return parts[1]
}

func verifyToken(secret, tokenB64 string) bool {
	raw, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 || parts[0] != "" {
		return false
	}
	authPart := parts[2]
	idx := strings.LastIndex(authPart, ":")
	if idx < 0 {
		return false
	}
	tsStr, provided := authPart[:idx], authPart[idx+1:]

	var ts int64
	fmt.Sscan(tsStr, &ts)
	diff := time.Now().Unix() - ts
	if diff > 300 || diff < -300 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("wgtunnel:" + tsStr))
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	return hmac.Equal([]byte(provided), []byte(expected))
}

// ── Framing ────────────────────────────────────────────────────────────────────
// Each WireGuard UDP datagram is length-prefixed: [2 bytes big-endian][payload]
// A zero-length frame is a keepalive — both sides ignore it.

func writeFrame(dst []byte, payloadLen int) {
	binary.BigEndian.PutUint16(dst[:frameHdrSize], uint16(payloadLen))
}

func readFrameLen(hdr []byte) int {
	return int(binary.BigEndian.Uint16(hdr))
}
