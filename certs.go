package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// generateCerts creates a self-signed CA and server certificate using ECDSA P-256.
// ECDSA P-256 is faster than RSA-2048 for both sign and verify, and produces
// smaller certs. No openssl CLI needed — pure Go standard library.
func generateCerts(hostname, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// ── Generate CA ───────────────────────────────────────────────────────────
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("CA key: %w", err)
	}

	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "smtp-wg-tunnel CA",
			Organization: []string{"Tunnel"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	// ── Generate server cert ──────────────────────────────────────────────────
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}

	srvSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	srvTemplate := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Mail Server"},
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}

	// ── Write PEM files ───────────────────────────────────────────────────────
	write := func(name string, pemType string, derBytes []byte, key *ecdsa.PrivateKey) error {
		path := filepath.Join(outDir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if key != nil {
			keyDER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return err
			}
			return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		}
		return pem.Encode(f, &pem.Block{Type: pemType, Bytes: derBytes})
	}

	if err := write("ca.key", "", nil, caKey); err != nil {
		return fmt.Errorf("write ca.key: %w", err)
	}
	if err := write("ca.crt", "CERTIFICATE", caDER, nil); err != nil {
		return fmt.Errorf("write ca.crt: %w", err)
	}
	if err := write("server.key", "", nil, srvKey); err != nil {
		return fmt.Errorf("write server.key: %w", err)
	}
	if err := write("server.crt", "CERTIFICATE", srvDER, nil); err != nil {
		return fmt.Errorf("write server.crt: %w", err)
	}

	fmt.Printf("\n✅  Certificates written to %q\n\n", outDir)
	fmt.Println("  server.crt  — server certificate (stays on VPS)")
	fmt.Println("  server.key  — server private key  (stays on VPS, keep secret)")
	fmt.Println("  ca.crt      — CA certificate      ← copy to client machine")
	fmt.Println("  ca.key      — CA private key       (stays on VPS, keep secret)")
	fmt.Println()
	return nil
}
