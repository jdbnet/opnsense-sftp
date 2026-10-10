package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen        string       `yaml:"listen"`
	LogLevel      string       `yaml:"log_level"`
	DataDir       string       `yaml:"data_dir"`
	KeysDir       string       `yaml:"keys_dir"`
	BackupsDir    string       `yaml:"backups_dir"`
	SessionSecret string       `yaml:"session_secret"`
	SFTP          SFTPConfig   `yaml:"sftp"`
	Prune         PruneConfig  `yaml:"prune"`
	Update        UpdateConfig `yaml:"update"`
	// StaleAfter is how long after the last successful backup a firewall counts as stale.
	// OPNsense pushes on its own schedule, which this app does not store, so the default is 48h.
	StaleAfter Duration `yaml:"stale_after"`
	// APIKeys are read-only credentials for the status API. Plaintext lives only in config;
	// startup stores a hash.
	APIKeys []APIKey `yaml:"api_keys"`
}

// APIKey is a configured read-only status API credential.
type APIKey struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

type UpdateConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	AllowDev bool   `yaml:"allow_dev"`
}

type SFTPConfig struct {
	Listen     string `yaml:"listen"`
	PublicHost string `yaml:"public_host"`
	PublicPort int    `yaml:"public_port"`
}

type PruneConfig struct {
	CheckInterval Duration `yaml:"check_interval"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func defaultConfig() *Config {
	return &Config{
		Listen:        "0.0.0.0:8080",
		LogLevel:      "info",
		DataDir:       "/var/lib/opnsense-sftp",
		KeysDir:       "/var/lib/opnsense-sftp/keys",
		BackupsDir:    "/var/lib/opnsense-sftp/backups",
		SessionSecret: "change-me",
		SFTP: SFTPConfig{
			Listen: "0.0.0.0:2222",
		},
		Prune: PruneConfig{
			CheckInterval: Duration{time.Hour},
		},
		Update: UpdateConfig{
			Enabled: true,
		},
		StaleAfter: Duration{48 * time.Hour},
	}
}

func (c *Config) SlogLevel() slog.Level {
	return ParseLogLevel(c.LogLevel)
}

func ParseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnv(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyEnv(cfg)
	return cfg, nil
}

func (c *Config) EnsureDirs() error {
	for _, dir := range []string{c.DataDir, c.KeysDir, c.BackupsDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.KeysDir), 0o755); err != nil {
		return err
	}
	return nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("OPNSENSE_SFTP_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("OPNSENSE_SFTP_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("OPNSENSE_SFTP_KEYS_DIR"); v != "" {
		cfg.KeysDir = v
	}
	if v := os.Getenv("OPNSENSE_SFTP_BACKUPS_DIR"); v != "" {
		cfg.BackupsDir = v
	}
	if v := os.Getenv("SESSION_SECRET"); v != "" {
		cfg.SessionSecret = v
	}
	if v := os.Getenv("SFTP_PUBLIC_HOST"); v != "" {
		cfg.SFTP.PublicHost = v
	}
	if v := os.Getenv("SFTP_PUBLIC_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SFTP.PublicPort = n
		}
	}
	if v := os.Getenv("OPNSENSE_SFTP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("OPNSENSE_SFTP_UPDATE_ENABLED"); v != "" {
		cfg.Update.Enabled = parseBool(v)
	}
	if v := os.Getenv("OPNSENSE_SFTP_UPDATE_URL"); v != "" {
		cfg.Update.URL = v
	}
	if v := os.Getenv("OPNSENSE_SFTP_STALE_AFTER"); v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			cfg.StaleAfter = Duration{d}
		}
	}
	if v := os.Getenv("OPNSENSE_SFTP_API_KEYS"); v != "" {
		cfg.APIKeys = mergeAPIKeys(cfg.APIKeys, parseAPIKeysEnv(v))
	}
	if cfg.StaleAfter.Duration <= 0 {
		cfg.StaleAfter = Duration{48 * time.Hour}
	}
}

// parseAPIKeysEnv parses comma-separated name:key pairs. The name is the text
// before the first colon, so the key itself may contain colons. Keys must not
// contain commas.
func parseAPIKeysEnv(v string) []APIKey {
	var out []APIKey
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, key, ok := strings.Cut(part, ":")
		name = strings.TrimSpace(name)
		key = strings.TrimSpace(key)
		if !ok || name == "" || key == "" {
			continue
		}
		out = append(out, APIKey{Name: name, Key: key})
	}
	return out
}

func mergeAPIKeys(base, extra []APIKey) []APIKey {
	out := append([]APIKey(nil), base...)
	index := make(map[string]int, len(out))
	for i, k := range out {
		index[k.Name] = i
	}
	for _, k := range extra {
		if i, ok := index[k.Name]; ok {
			out[i] = k
			continue
		}
		index[k.Name] = len(out)
		out = append(out, k)
	}
	return out
}

func parseBool(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}
