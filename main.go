package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	log.SetFlags(log.Ltime)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		serverCmd(os.Args[2:])
	case "client":
		clientCmd(os.Args[2:])
	case "generate-certs":
		certsCmd(os.Args[2:])
	case "add-user":
		addUserCmd(os.Args[2:])
	case "version":
		fmt.Println("smtp-wg-tunnel (Go) — WireGuard over SMTP-disguised TLS")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`smtp-wg-tunnel — WireGuard over SMTP-disguised TLS (Go edition)

Commands:
  server  -c server_config.yaml     Run the VPS-side tunnel server
  client  -c client_config.yaml     Run the local WireGuard proxy
  generate-certs <hostname> [-o dir] Generate TLS certificates (no openssl needed)
  add-user <username>               Print a new user entry for users.yaml
  version                           Print version info

Build:
  go build -o smtp-wg-tunnel .               (Linux / macOS)
  GOOS=windows go build -o smtp-wg-tunnel.exe .  (cross-compile for Windows)

`)
}

// ── server subcommand ──────────────────────────────────────────────────────────

func serverCmd(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := fs.String("c", "server_config.yaml", "server config file")
	_ = fs.Bool("d", false, "debug logging (reserved)")
	fs.Parse(args)

	cfg, err := loadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("Config: %v", err)
	}
	users, err := loadUsers(cfg.UsersFile)
	if err != nil {
		log.Printf("Warning — users file: %v", err)
		users = Users{}
	}

	srv := NewServer(cfg, users)

	// Graceful shutdown on SIGINT / SIGTERM
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	srv.Run()
}

// ── client subcommand ──────────────────────────────────────────────────────────

func clientCmd(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configPath := fs.String("c", "client_config.yaml", "client config file")
	wgConfig   := fs.String("wg", "", "path to wg0.conf — enables embedded WireGuard (no WireGuard-Windows needed)")
	_ = fs.Bool("d", false, "debug logging (reserved)")
	fs.Parse(args)

	cfg, err := loadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Config: %v", err)
	}
	if cfg.ServerHost == "" {
		log.Fatal("server_host not set in config")
	}
	if cfg.Secret == "" {
		log.Fatal("secret not set in config")
	}

	cl := NewClient(cfg)

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Println("Stopping...")
		cl.Stop()
		os.Exit(0)
	}()

	if *wgConfig != "" {
		wgCfg, err := parseWGConfig(*wgConfig)
		if err != nil {
			log.Fatalf("WireGuard config: %v", err)
		}
		if len(wgCfg.Peers) == 0 {
			log.Fatal("wg0.conf has no [Peer] section")
		}
		log.Printf("Embedded WireGuard mode — config: %s", *wgConfig)
		log.Printf("Peer: %s…  AllowedIPs: %s",
			wgCfg.Peers[0].PublicKey[:8],
			strings.Join(wgCfg.Peers[0].AllowedIPs, ", "))
		cl.RunWGMode(wgCfg)
		return
	}

	// Legacy UDP proxy mode (WireGuard-Windows app points Endpoint here)
	cl.Run()
}

// ── generate-certs subcommand ──────────────────────────────────────────────────

func certsCmd(args []string) {
	fs := flag.NewFlagSet("generate-certs", flag.ExitOnError)
	outDir := fs.String("o", ".", "output directory")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: smtp-wg-tunnel generate-certs <hostname> [-o dir]")
		os.Exit(1)
	}
	hostname := fs.Arg(0)
	if err := generateCerts(hostname, *outDir); err != nil {
		log.Fatalf("generate-certs: %v", err)
	}
}

// ── add-user subcommand ────────────────────────────────────────────────────────

func addUserCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: smtp-wg-tunnel add-user <username>")
		os.Exit(1)
	}
	username := args[0]
	secret, err := generateSecret()
	if err != nil {
		log.Fatalf("generate secret: %v", err)
	}
	fmt.Printf("\nAdd to users.yaml:\n\nusers:\n  %s:\n    secret: \"%s\"\n\n", username, secret)
	fmt.Printf("Add to client_config.yaml:\n\n  username: \"%s\"\n  secret:   \"%s\"\n\n", username, secret)
}
