package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
)

func testService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db), db
}

func TestAPIKeyMiddleware(t *testing.T) {
	svc, _ := testService(t)
	raw, rec, err := svc.CreateAPIKey("dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || rec.Prefix == "" || len(rec.Prefix) > len(raw) {
		t.Fatalf("unexpected key material: prefix %q", rec.Prefix)
	}

	var saw *Actor
	next := svc.APIKeyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = ActorFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	recMissing := httptest.NewRecorder()
	next.ServeHTTP(recMissing, missing)
	if recMissing.Code != http.StatusUnauthorized {
		t.Fatalf("missing key: got %d", recMissing.Code)
	}

	invalid := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	invalid.Header.Set("Authorization", "Bearer not-a-real-key")
	recInvalid := httptest.NewRecorder()
	next.ServeHTTP(recInvalid, invalid)
	if recInvalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid key: got %d", recInvalid.Code)
	}

	post := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	post.Header.Set("Authorization", "Bearer "+raw)
	recPost := httptest.NewRecorder()
	next.ServeHTTP(recPost, post)
	if recPost.Code != http.StatusUnauthorized {
		t.Fatalf("non-read method: got %d", recPost.Code)
	}

	bearer := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	bearer.Header.Set("Authorization", "Bearer "+raw)
	recBearer := httptest.NewRecorder()
	next.ServeHTTP(recBearer, bearer)
	if recBearer.Code != http.StatusNoContent {
		t.Fatalf("bearer: got %d body %s", recBearer.Code, recBearer.Body.String())
	}
	if saw == nil || saw.Type != "api_key" || saw.ID != "dashboard" {
		t.Fatalf("actor: %+v", saw)
	}

	header := httptest.NewRequest(http.MethodGet, "/api/v1/backups/status", nil)
	header.Header.Set("X-API-Key", raw)
	recHeader := httptest.NewRecorder()
	next.ServeHTTP(recHeader, header)
	if recHeader.Code != http.StatusNoContent {
		t.Fatalf("x-api-key: got %d", recHeader.Code)
	}

	both := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	both.Header.Set("Authorization", "Bearer wrong")
	both.Header.Set("X-API-Key", raw)
	recBoth := httptest.NewRecorder()
	next.ServeHTTP(recBoth, both)
	if recBoth.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer must not fall back to X-API-Key: got %d", recBoth.Code)
	}

	if err := svc.RevokeAPIKey(rec.ID); err != nil {
		t.Fatal(err)
	}
	revoked := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	revoked.Header.Set("X-API-Key", raw)
	recRevoked := httptest.NewRecorder()
	next.ServeHTTP(recRevoked, revoked)
	if recRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d", recRevoked.Code)
	}
}

func TestSyncConfigAPIKeys(t *testing.T) {
	svc, db := testService(t)
	if err := svc.SyncConfigAPIKeys([]NamedKey{{Name: "dashboard", Key: "config-secret-value"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetActiveAPIKeyByHash(HashAPIKey("config-secret-value")); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.SQL.QueryRow(`SELECT key_hash FROM api_keys WHERE name = ?`, "dashboard").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "config-secret-value" {
		t.Fatal("stored plaintext key")
	}

	keys, err := svc.ListAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Source != store.APIKeySourceConfig {
		t.Fatalf("keys: %+v", keys)
	}
	if err := svc.RevokeAPIKey(keys[0].ID); err != ErrAPIKeyFromConfig {
		t.Fatalf("revoke config key: %v", err)
	}

	if err := svc.SyncConfigAPIKeys(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetActiveAPIKeyByHash(HashAPIKey("config-secret-value")); err == nil {
		t.Fatal("removed config key should be revoked")
	}
}

func TestCreateAPIKeyHidesSecretOnList(t *testing.T) {
	svc, _ := testService(t)
	raw, _, err := svc.CreateAPIKey("homelab")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("len %d", len(listed))
	}
	if listed[0].KeyHash == raw || listed[0].Prefix == raw {
		t.Fatal("list exposed full key")
	}
	if listed[0].KeyHash != HashAPIKey(raw) {
		t.Fatal("hash mismatch")
	}
}
