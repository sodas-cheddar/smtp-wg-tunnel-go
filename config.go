package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── Server config ──────────────────────────────────────────────────────────────

type ServerConfig struct {
	Host      string
	Port      int
	Hostname  string
	CertFile  string
	KeyFile   string
	WGHost    string
	WGPort    int
	UsersFile string
}

func loadServerConfig(path string) (*ServerConfig, error) {
	m, err := parseYAML(path)
	if err != nil {
		return nil, err
	}
	cfg := &ServerConfig{
		Host:      "0.0.0.0",
		Port:      587,
		Hostname:  "mail.example.com",
		CertFile:  "server.crt",
		KeyFile:   "server.key",
		WGHost:    "127.0.0.1",
		WGPort:    51820,
		UsersFile: "users.yaml",
	}
	if v, ok := m["server.host"]; ok {
		cfg.Host = v
	}
	if v, ok := m["server.port"]; ok {
		fmt.Sscan(v, &cfg.Port)
	}
	if v, ok := m["server.hostname"]; ok {
		cfg.Hostname = v
	}
	if v, ok := m["server.cert_file"]; ok {
		cfg.CertFile = v
	}
	if v, ok := m["server.key_file"]; ok {
		cfg.KeyFile = v
	}
	if v, ok := m["server.wg_host"]; ok {
		cfg.WGHost = v
	}
	if v, ok := m["server.wg_port"]; ok {
		fmt.Sscan(v, &cfg.WGPort)
	}
	if v, ok := m["server.users_file"]; ok {
		cfg.UsersFile = v
	}
	return cfg, nil
}

// ── Client config ──────────────────────────────────────────────────────────────

type ClientConfig struct {
	ServerHost     string
	ServerPort     int
	LocalWGHost    string
	LocalWGPort    int
	Username       string
	Secret         string
	CACert         string
	ReconnectDelay time.Duration
}

func loadClientConfig(path string) (*ClientConfig, error) {
	m, err := parseYAML(path)
	if err != nil {
		return nil, err
	}
	cfg := &ClientConfig{
		ServerPort:     587,
		LocalWGHost:    "127.0.0.1",
		LocalWGPort:    51820,
		ReconnectDelay: 5 * time.Second,
	}
	if v, ok := m["client.server_host"]; ok {
		cfg.ServerHost = v
	}
	if v, ok := m["client.server_port"]; ok {
		fmt.Sscan(v, &cfg.ServerPort)
	}
	if v, ok := m["client.local_wg_host"]; ok {
		cfg.LocalWGHost = v
	}
	if v, ok := m["client.local_wg_port"]; ok {
		fmt.Sscan(v, &cfg.LocalWGPort)
	}
	if v, ok := m["client.username"]; ok {
		cfg.Username = v
	}
	if v, ok := m["client.secret"]; ok {
		cfg.Secret = v
	}
	if v, ok := m["client.ca_cert"]; ok && v != "null" && v != "~" {
		cfg.CACert = v
	}
	if v, ok := m["client.reconnect_delay"]; ok {
		var secs int
		fmt.Sscan(v, &secs)
		cfg.ReconnectDelay = time.Duration(secs) * time.Second
	}
	return cfg, nil
}

// ── Users database ─────────────────────────────────────────────────────────────

type Users map[string]string // username → secret

func loadUsers(path string) (Users, error) {
	m, err := parseYAML(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Users{}, nil
		}
		return nil, err
	}
	users := Users{}
	// Keys are "users.<username>.secret"
	for k, v := range m {
		parts := strings.SplitN(k, ".", 3)
		if len(parts) == 3 && parts[0] == "users" && parts[2] == "secret" {
			users[parts[1]] = v
		}
	}
	return users, nil
}

// ── Minimal YAML parser ────────────────────────────────────────────────────────
// Handles our specific config format: section headers at indent 0,
// key-value pairs at indent 2, nested key-value pairs at indent 4.
// Returns a flat map of "section.key" or "section.subsection.key" → "value".

func parseYAML(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	var section, subsection string

	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = line[:idx]
		}
		stripped := strings.TrimRight(line, " \t")
		if stripped == "" {
			continue
		}

		// Count leading spaces for indent level
		indent := 0
		for _, c := range stripped {
			if c == ' ' {
				indent++
			} else {
				break
			}
		}
		trimmed := strings.TrimSpace(stripped)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Split on first colon
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := strings.TrimSpace(trimmed[colonIdx+1:])
		val = strings.Trim(val, `"'`)

		switch indent {
		case 0:
			section = key
			subsection = ""
		case 2:
			if val == "" {
				subsection = key // e.g. a username in users.yaml
			} else {
				result[section+"."+key] = val
			}
		case 4:
			if subsection != "" {
				result[section+"."+subsection+"."+key] = val
			}
		}
	}
	return result, scanner.Err()
}
