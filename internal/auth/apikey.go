package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
)

const apiKeyPrefix = "oss_"

var (
	ErrAPIKeyNotFound   = errors.New("api key not found")
	ErrAPIKeyFromConfig = errors.New("api key is managed from configuration")
)

// NamedKey is a plaintext API key from config or the environment.
type NamedKey struct {
	Name string
	Key  string
}

// HashAPIKey returns the hex SHA-256 of a raw API key.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func keyPrefix(raw string) string {
	if len(raw) <= 12 {
		return raw
	}
	return raw[:12]
}

// CreateAPIKey generates a read-only key, stores only its hash, and returns the
// plaintext once.
func (s *Service) CreateAPIKey(name string) (string, *store.APIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, fmt.Errorf("name is required")
	}
	if len(name) > 128 {
		return "", nil, fmt.Errorf("name is too long")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	raw := apiKeyPrefix + hex.EncodeToString(buf)
	rec, err := s.db.CreateAPIKey(name, keyPrefix(raw), HashAPIKey(raw), store.APIKeySourceUI)
	if err != nil {
		return "", nil, err
	}
	return raw, rec, nil
}

func (s *Service) ListAPIKeys() ([]store.APIKey, error) {
	return s.db.ListActiveAPIKeys()
}

func (s *Service) RevokeAPIKey(id int64) error {
	rec, err := s.db.GetAPIKey(id)
	if err != nil {
		return ErrAPIKeyNotFound
	}
	if rec.Source == store.APIKeySourceConfig {
		return ErrAPIKeyFromConfig
	}
	if rec.RevokedAt != nil {
		return nil
	}
	return s.db.RevokeAPIKey(id)
}

// SyncConfigAPIKeys hashes configured keys and upserts them. Removed config
// keys are revoked. The plaintext is not stored. Later entries with the same
// name win.
func (s *Service) SyncConfigAPIKeys(keys []NamedKey) error {
	last := make(map[string]store.ConfigAPIKey, len(keys))
	order := make([]string, 0, len(keys))
	for _, k := range keys {
		name := strings.TrimSpace(k.Name)
		raw := strings.TrimSpace(k.Key)
		if name == "" || raw == "" {
			continue
		}
		if _, ok := last[name]; !ok {
			order = append(order, name)
		}
		last[name] = store.ConfigAPIKey{
			Name:   name,
			Prefix: keyPrefix(raw),
			Hash:   HashAPIKey(raw),
		}
	}
	hashed := make([]store.ConfigAPIKey, 0, len(order))
	for _, name := range order {
		hashed = append(hashed, last[name])
	}
	return s.db.SyncConfigAPIKeys(hashed)
}

func apiKeyFromRequest(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header != "" {
		const scheme = "bearer "
		if len(header) >= len(scheme) && strings.EqualFold(header[:len(scheme)], scheme) {
			return strings.TrimSpace(header[len(scheme):])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// APIKeyMiddleware authenticates a read-only status request. Non-read methods
// are rejected so a key cannot be used to change anything if the middleware is
// mounted more widely than the status routes.
func (s *Service) APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeUnauthorized(w)
			return
		}
		raw := apiKeyFromRequest(r)
		if raw == "" {
			writeUnauthorized(w)
			return
		}
		rec, err := s.db.GetActiveAPIKeyByHash(HashAPIKey(raw))
		if err != nil || rec == nil {
			writeUnauthorized(w)
			return
		}
		actor := &Actor{Type: "api_key", ID: rec.Name}
		next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
}
