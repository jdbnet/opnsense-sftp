package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/auth"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/config"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/keys"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
)

func testServer(t *testing.T, stale time.Duration) (*Server, *store.DB, *auth.Service) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{
		StaleAfter: config.Duration{Duration: stale},
		BackupsDir: filepath.Join(dir, "backups"),
		KeysDir:    filepath.Join(dir, "keys"),
		DataDir:    dir,
	}
	authSvc := auth.New(db)
	srv := New(cfg, authSvc, db, keys.NewManager(cfg.KeysDir), true, "1.2.3")
	return srv, db, authSvc
}

func TestOverallAndStale(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	exact := now.Add(-48 * time.Hour)
	if backupStale(&exact, now, 48*time.Hour) {
		t.Fatal("a backup exactly at the interval is not stale")
	}
	older := exact.Add(-time.Second)
	if !backupStale(&older, now, 48*time.Hour) {
		t.Fatal("a backup older than the interval is stale")
	}
	if backupStale(nil, now, 48*time.Hour) {
		t.Fatal("missing success is not stale")
	}

	if overallStatus(nil) != "unknown" {
		t.Fatal("no jobs")
	}
	if overallStatus([]backupJob{{Enabled: false, LastStatus: "failed"}}) != "unknown" {
		t.Fatal("disabled jobs do not count")
	}
	if overallStatus([]backupJob{{Enabled: true, LastStatus: "success"}}) != "ok" {
		t.Fatal("healthy")
	}
	if overallStatus([]backupJob{{Enabled: true, LastStatus: "running"}}) != "ok" {
		t.Fatal("running without stale or failure is ok")
	}
	if overallStatus([]backupJob{
		{Enabled: true, LastStatus: "success", Stale: true},
		{Enabled: true, LastStatus: "success"},
	}) != "warning" {
		t.Fatal("stale")
	}
	if overallStatus([]backupJob{{Enabled: true, LastStatus: "never_run"}}) != "warning" {
		t.Fatal("never run")
	}
	if overallStatus([]backupJob{{Enabled: true, LastStatus: "partial"}}) != "warning" {
		t.Fatal("partial")
	}
	if overallStatus([]backupJob{
		{Enabled: true, LastStatus: "failed"},
		{Enabled: true, LastStatus: "never_run", Stale: true},
	}) != "failing" {
		t.Fatal("failed takes priority")
	}
}

func TestStatusEndpoints(t *testing.T) {
	srv, db, authSvc := testServer(t, 48*time.Hour)
	raw, _, err := authSvc.CreateAPIKey("dashboard")
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	noAuth := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, noAuth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("health missing key: %d %s", rec.Code, rec.Body.String())
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	healthReq.Header.Set("Authorization", "Bearer "+raw)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health: %d %s", healthRec.Code, healthRec.Body.String())
	}
	var health healthResponse
	if err := json.Unmarshal(healthRec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health.App != "opnsense-sftp" || health.Version != "1.2.3" || health.Status != "ok" {
		t.Fatalf("health body: %+v", health)
	}

	emptyReq := httptest.NewRequest(http.MethodGet, "/api/v1/backups/status", nil)
	emptyReq.Header.Set("X-API-Key", raw)
	emptyRec := httptest.NewRecorder()
	handler.ServeHTTP(emptyRec, emptyReq)
	if emptyRec.Code != http.StatusOK {
		t.Fatalf("empty status: %d %s", emptyRec.Code, emptyRec.Body.String())
	}
	var empty backupStatusResponse
	if err := json.Unmarshal(emptyRec.Body.Bytes(), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Overall != "unknown" || len(empty.Jobs) != 0 || empty.App != "opnsense-sftp" || empty.Version != "1.2.3" {
		t.Fatalf("empty status: %+v", empty)
	}
	if _, err := time.Parse(time.RFC3339, empty.GeneratedAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(emptyRec.Body.String(), `"jobs":[]`) && !strings.Contains(emptyRec.Body.String(), `"jobs": []`) {
		t.Fatalf("jobs should be an empty array: %s", emptyRec.Body.String())
	}

	if _, err := db.CreateInstance("Home firewall", "home", "key-home", "lan"); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.CreateInstance("Office", "office", "key-office", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordBackup(fresh.ID, "old.xml", "/tmp/old.xml", 10); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordBackup(fresh.ID, "new.xml", "/tmp/new.xml", 25); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	if _, err := db.SQL.Exec(`UPDATE backups SET uploaded_at = ? WHERE instance_id = ? AND filename = ?`, old, fresh.ID, "old.xml"); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := db.SQL.Exec(`UPDATE backups SET uploaded_at = ? WHERE instance_id = ? AND filename = ?`, recent, fresh.ID, "new.xml"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL.Exec(`UPDATE opnsense_instances SET last_backup = ? WHERE id = ?`, recent, fresh.ID); err != nil {
		t.Fatal(err)
	}

	staleInst, err := db.CreateInstance("Cabin", "cabin", "key-cabin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordBackup(staleInst.ID, "cabin.xml", "/tmp/cabin.xml", 4); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL.Exec(`UPDATE backups SET uploaded_at = ? WHERE instance_id = ?`, old, staleInst.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL.Exec(`UPDATE opnsense_instances SET last_backup = ? WHERE id = ?`, old, staleInst.ID); err != nil {
		t.Fatal(err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/backups/status", nil)
	statusReq.Header.Set("Authorization", "Bearer "+raw)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", statusRec.Code, statusRec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["overall"] != "warning" {
		t.Fatalf("overall: %v body %s", body["overall"], statusRec.Body.String())
	}
	jobs, _ := body["jobs"].([]any)
	if len(jobs) != 3 {
		t.Fatalf("jobs: %s", statusRec.Body.String())
	}
	byID := map[string]map[string]any{}
	for _, rawJob := range jobs {
		job := rawJob.(map[string]any)
		byID[job["id"].(string)] = job
	}
	home := byID["home"]
	if home["last_status"] != "never_run" || home["stale"] != false || home["enabled"] != true {
		t.Fatalf("home: %+v", home)
	}
	if home["last_run_at"] != nil || home["last_success_at"] != nil || home["last_error"] != nil || home["next_run_at"] != nil || home["last_duration_seconds"] != nil || home["last_size_bytes"] != nil {
		t.Fatalf("home unknowns: %+v", home)
	}
	if home["name"] != "Home firewall" || home["target"] != "home" {
		t.Fatalf("home identity: %+v", home)
	}

	office := byID["office"]
	if office["last_status"] != "success" || office["stale"] != false || office["last_size_bytes"] != float64(25) {
		t.Fatalf("office: %+v", office)
	}
	if office["last_run_at"] != recent || office["last_success_at"] != recent {
		t.Fatalf("office times: %+v", office)
	}
	if office["last_duration_seconds"] != nil || office["last_error"] != nil || office["next_run_at"] != nil {
		t.Fatalf("office unknowns: %+v", office)
	}

	cabin := byID["cabin"]
	if cabin["last_status"] != "success" || cabin["stale"] != true || cabin["last_size_bytes"] != float64(4) {
		t.Fatalf("cabin: %+v", cabin)
	}

	mutate := httptest.NewRequest(http.MethodDelete, "/api/v1/backups/1", nil)
	mutate.Header.Set("Authorization", "Bearer "+raw)
	mutateRec := httptest.NewRecorder()
	handler.ServeHTTP(mutateRec, mutate)
	if mutateRec.Code != http.StatusUnauthorized {
		t.Fatalf("api key must not delete backups: %d %s", mutateRec.Code, mutateRec.Body.String())
	}

	sessionOnly := httptest.NewRequest(http.MethodGet, "/api/v1/backups/status", nil)
	sessionOnly.AddCookie(&http.Cookie{Name: "opnsense_sftp_session", Value: "nope"})
	sessionRec := httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionOnly)
	if sessionRec.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie is not an API key: %d", sessionRec.Code)
	}
}

func TestAPIKeyManagement(t *testing.T) {
	srv, db, authSvc := testServer(t, time.Hour)
	if _, err := authSvc.CreateUser("admin", "password123", true); err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.CreateUser("viewer", "password123", false); err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	adminCookie := loginCookie(t, handler, "admin", "password123")
	viewerCookie := loginCookie(t, handler, "viewer", "password123")

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"dashboard"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(adminCookie)
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID     int64  `json:"id"`
		Key    string `json:"key"`
		Prefix string `json:"prefix"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, "oss_") || !strings.HasPrefix(created.Key, created.Prefix) || created.Source != "ui" {
		t.Fatalf("created: %+v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), created.Key) {
		t.Fatal("list response included the full key")
	}

	var hash string
	if err := db.SQL.QueryRow(`SELECT key_hash FROM api_keys WHERE id = ?`, created.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == created.Key || hash == "" {
		t.Fatal("expected stored hash")
	}

	forbidden := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	forbidden.AddCookie(viewerCookie)
	forbiddenRec := httptest.NewRecorder()
	handler.ServeHTTP(forbiddenRec, forbidden)
	if forbiddenRec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", forbiddenRec.Code)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/backups/status", nil)
	statusReq.Header.Set("X-API-Key", created.Key)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status with created key: %d %s", statusRec.Code, statusRec.Body.String())
	}

	instances := httptest.NewRequest(http.MethodGet, "/api/v1/instances", nil)
	instances.Header.Set("X-API-Key", created.Key)
	instancesRec := httptest.NewRecorder()
	handler.ServeHTTP(instancesRec, instances)
	if instancesRec.Code != http.StatusUnauthorized {
		t.Fatalf("api key must not list instances: %d", instancesRec.Code)
	}

	sessionInstances := httptest.NewRequest(http.MethodGet, "/api/v1/instances", nil)
	sessionInstances.AddCookie(adminCookie)
	sessionInstancesRec := httptest.NewRecorder()
	handler.ServeHTTP(sessionInstancesRec, sessionInstances)
	if sessionInstancesRec.Code != http.StatusOK {
		t.Fatalf("session list instances: %d %s", sessionInstancesRec.Code, sessionInstancesRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+strconv.FormatInt(created.ID, 10), nil)
	revokeReq.AddCookie(adminCookie)
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", revokeRec.Code, revokeRec.Body.String())
	}
	after := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	after.Header.Set("Authorization", "Bearer "+created.Key)
	afterRec := httptest.NewRecorder()
	handler.ServeHTTP(afterRec, after)
	if afterRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key still worked: %d", afterRec.Code)
	}
}

func loginCookie(t *testing.T, handler http.Handler, username, password string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", username, rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "opnsense_sftp_session" {
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}

func TestConfigEnvAPIKeys(t *testing.T) {
	t.Setenv("OPNSENSE_SFTP_API_KEYS", "dashboard:alpha:beta, other:gamma")
	t.Setenv("OPNSENSE_SFTP_STALE_AFTER", "72h")
	cfg, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StaleAfter.Duration != 72*time.Hour {
		t.Fatalf("stale: %s", cfg.StaleAfter.Duration)
	}
	if len(cfg.APIKeys) != 2 || cfg.APIKeys[0].Name != "dashboard" || cfg.APIKeys[0].Key != "alpha:beta" || cfg.APIKeys[1].Key != "gamma" {
		t.Fatalf("keys: %+v", cfg.APIKeys)
	}
}
