package api

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/auth"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/config"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/keys"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/prune"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/ui"
)

type Server struct {
	cfg      *config.Config
	auth     *auth.Service
	db       *store.DB
	keys     *keys.Manager
	hasUsers bool
	version  string
}

func New(cfg *config.Config, authSvc *auth.Service, db *store.DB, keysMgr *keys.Manager, hasUsers bool, version string) *Server {
	return &Server{cfg: cfg, auth: authSvc, db: db, keys: keysMgr, hasUsers: hasUsers, version: version}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/auth/status", s.authStatus)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/login/totp", s.loginTOTP)

	prot := http.NewServeMux()
	prot.HandleFunc("POST /api/v1/auth/logout", s.logout)
	prot.HandleFunc("GET /api/v1/auth/me", s.me)
	prot.HandleFunc("PUT /api/v1/profile", s.updateProfile)
	prot.HandleFunc("POST /api/v1/profile/totp/generate", s.generateTOTP)
	prot.HandleFunc("POST /api/v1/profile/totp/enable", s.enableTOTP)
	prot.HandleFunc("POST /api/v1/profile/totp/disable", s.disableTOTP)
	prot.HandleFunc("GET /api/v1/users", auth.RequireAdmin(s.listUsers))
	prot.HandleFunc("POST /api/v1/users", auth.RequireAdmin(s.createUser))
	prot.HandleFunc("PUT /api/v1/users/{id}/toggle-admin", auth.RequireAdmin(s.toggleAdmin))
	prot.HandleFunc("DELETE /api/v1/users/{id}", auth.RequireAdmin(s.deleteUser))
	prot.HandleFunc("GET /api/v1/dashboard", s.dashboard)
	prot.HandleFunc("GET /api/v1/instances", s.listInstances)
	prot.HandleFunc("POST /api/v1/instances", s.createInstance)
	prot.HandleFunc("GET /api/v1/instances/{id}", s.getInstance)
	prot.HandleFunc("GET /api/v1/instances/{id}/private-key", s.downloadPrivateKey)
	prot.HandleFunc("GET /api/v1/backups", s.listBackups)
	prot.HandleFunc("GET /api/v1/backups/{id}/download", s.downloadBackup)
	prot.HandleFunc("DELETE /api/v1/backups/{id}", s.deleteBackup)
	prot.HandleFunc("GET /api/v1/prune/settings", s.getPruneSettings)
	prot.HandleFunc("PUT /api/v1/prune/settings", s.updatePruneSettings)
	prot.HandleFunc("POST /api/v1/prune/run", s.runPrune)

	mux.Handle("/api/v1/", s.auth.Middleware(prot))
	mux.Handle("/", spaHandler())
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := false
	if token := auth.SessionToken(r); token != "" {
		if _, err := s.auth.SessionUser(token); err == nil {
			authenticated = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_required": s.hasUsers,
		"authenticated": authenticated,
		"version":       s.version,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.auth.Authenticate(req.Username, req.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if u.TOTPEnabled {
		pending, err := s.auth.CreatePendingTOTP(u.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"totp_required": true, "pending_token": pending})
		return
	}
	token, err := s.auth.CreateSession(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	auth.SetSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": auth.ToPublicUser(u)})
}

func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken string `json:"pending_token"`
		Code         string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.auth.VerifyPendingTOTP(req.PendingToken, req.Code)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid totp code")
		return
	}
	token, err := s.auth.CreateSession(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	auth.SetSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": auth.ToPublicUser(u)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if token := auth.SessionToken(r); token != "" {
		_ = s.auth.DeleteSession(token)
	}
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, auth.ActorFrom(r.Context()))
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	a := auth.ActorFrom(r.Context())
	if a == nil || a.User == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username != "" && req.Username != a.User.Username {
		if err := s.auth.UpdateUsername(a.User.ID, req.Username); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.NewPassword != "" {
		if err := s.auth.ChangePassword(a.User.ID, req.CurrentPassword, req.NewPassword); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	u, err := s.db.GetUserByID(a.User.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, auth.ToPublicUser(u))
}

func (s *Server) generateTOTP(w http.ResponseWriter, r *http.Request) {
	a := auth.ActorFrom(r.Context())
	secret, uri, err := s.auth.GenerateTOTPSecret(a.User.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri})
}

func (s *Server) enableTOTP(w http.ResponseWriter, r *http.Request) {
	a := auth.ActorFrom(r.Context())
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.auth.EnableTOTP(a.User.ID, req.Code); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	a := auth.ActorFrom(r.Context())
	if err := s.auth.DisableTOTP(a.User.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	u, err := s.auth.CreateUser(req.Username, req.Password, req.IsAdmin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) toggleAdmin(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.db.GetUserByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.auth.ToggleAdmin(id, !u.IsAdmin); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, _ = s.db.GetUserByID(id)
	writeJSON(w, http.StatusOK, auth.ToPublicUser(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	a := auth.ActorFrom(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.User != nil && a.User.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	if err := s.auth.DeleteUser(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	instances, _ := s.db.CountInstances()
	backups, _ := s.db.CountBackups()
	totalSize, _ := s.db.TotalBackupSize()
	publicPort := s.cfg.SFTP.PublicPort
	if publicPort == 0 {
		if _, port, err := netSplitHostPort(s.cfg.SFTP.Listen); err == nil {
			publicPort = port
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"instance_count": instances,
		"backup_count":   backups,
		"total_size":     totalSize,
		"sftp_port":      publicPort,
		"sftp_host":      s.cfg.SFTP.PublicHost,
	})
}

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	instances, err := s.db.ListInstances()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if instances == nil {
		instances = []store.Instance{}
	}
	out := make([]map[string]any, 0, len(instances))
	for _, inst := range instances {
		out = append(out, s.instanceResponse(inst, r))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Identifier  string `json:"identifier"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" || req.Identifier == "" {
		writeErr(w, http.StatusBadRequest, "name and identifier required")
		return
	}
	if _, err := s.db.GetInstanceByIdentifier(req.Identifier); err == nil {
		writeErr(w, http.StatusBadRequest, "identifier already exists")
		return
	}
	keyID, privatePath, publicKey, err := s.keys.GenerateKeyPair()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	inst, err := s.db.CreateInstance(req.Name, req.Identifier, keyID, req.Description)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.SaveSSHKey(keyID, inst.ID, publicKey, privatePath); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = prune.EnsureBackupDir(s.cfg.BackupsDir, req.Identifier)
	resp := s.instanceResponse(*inst, r)
	resp["public_key"] = publicKey
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	inst, err := s.db.GetInstanceByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "instance not found")
		return
	}
	resp := s.instanceResponse(*inst, r)
	sshKey, err := s.db.GetSSHKeyByKeyID(inst.SSHKeyID)
	if err == nil {
		resp["public_key"] = sshKey.PublicKey
	}
	backups, _ := s.db.GetBackupsForInstance(id)
	if backups == nil {
		backups = []store.Backup{}
	}
	resp["recent_backups"] = backups
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) downloadPrivateKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	inst, err := s.db.GetInstanceByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "instance not found")
		return
	}
	data, err := s.keys.LoadPrivateKey(inst.SSHKeyID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "private key not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_key"`, inst.Identifier))
	_, _ = w.Write(data)
}

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 25
	}
	var instanceID *int64
	if v := r.URL.Query().Get("instance_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid instance_id")
			return
		}
		instanceID = &id
	}
	offset := (page - 1) * perPage
	backups, total, err := s.db.ListBackups(instanceID, perPage, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if backups == nil {
		backups = []store.Backup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":     backups,
		"total":     total,
		"page":      page,
		"per_page":  perPage,
		"pages":     (total + perPage - 1) / perPage,
	})
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	backup, err := s.db.GetBackupByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}
	f, err := os.Open(backup.FilePath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "file not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, backup.Filename))
	_, _ = io.Copy(w, f)
}

func (s *Server) deleteBackup(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	backup, err := s.db.GetBackupByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}
	_ = os.Remove(backup.FilePath)
	if err := s.db.DeleteBackup(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getPruneSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.GetPruneSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) updatePruneSettings(w http.ResponseWriter, r *http.Request) {
	var req store.PruneSettings
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ScopeType != "all" && req.ScopeType != "instance" {
		writeErr(w, http.StatusBadRequest, "invalid scope_type")
		return
	}
	if req.KeepDays != nil && req.KeepCount != nil {
		writeErr(w, http.StatusBadRequest, "only one of keep_days or keep_count allowed")
		return
	}
	if req.IntervalSeconds < 60 {
		req.IntervalSeconds = 86400
	}
	req.ID = 1
	if err := s.db.UpsertPruneSettings(req); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	settings, _ := s.db.GetPruneSettings()
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) runPrune(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType       string `json:"scope_type"`
		ScopeInstanceID *int64 `json:"scope_instance_id"`
		KeepDays        *int   `json:"keep_days"`
		KeepCount       *int   `json:"keep_count"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := prune.Run(s.db, req.ScopeType, req.ScopeInstanceID, req.KeepDays, req.KeepCount)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) instanceResponse(inst store.Instance, r *http.Request) map[string]any {
	host := s.cfg.SFTP.PublicHost
	if host == "" {
		host = r.Host
		if h, _, err := netSplitHostPort(host); err == nil {
			host = h
		}
	}
	port := s.cfg.SFTP.PublicPort
	if port == 0 {
		_, port, _ = netSplitHostPort(s.cfg.SFTP.Listen)
	}
	var uri string
	if port == 22 {
		uri = fmt.Sprintf("sftp://%s@%s//%s", inst.Identifier, host, inst.Identifier)
	} else {
		uri = fmt.Sprintf("sftp://%s@%s:%d//%s", inst.Identifier, host, port, inst.Identifier)
	}
	return map[string]any{
		"id":          inst.ID,
		"name":        inst.Name,
		"identifier":  inst.Identifier,
		"ssh_key_id":  inst.SSHKeyID,
		"description": inst.Description,
		"last_backup": inst.LastBackup,
		"created_at":  inst.CreatedAt,
		"sftp_uri":    uri,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func pathID(r *http.Request, name string) (int64, error) {
	v := r.PathValue(name)
	return strconv.ParseInt(v, 10, 64)
}

func netSplitHostPort(listen string) (string, int, error) {
	host, portStr, err := splitHostPort(listen)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	return host, port, err
}

func splitHostPort(s string) (string, string, error) {
	if strings.HasPrefix(s, ":") {
		return "", strings.TrimPrefix(s, ":"), nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "8080", nil
	}
	return s[:i], s[i+1:], nil
}

func spaHandler() http.Handler {
	sub, err := fs.Sub(ui.FS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "ui not built", http.StatusNotFound)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			clean := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
			if f, err := sub.Open(clean); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		index, err := sub.Open("index.html")
		if err != nil {
			http.Error(w, "ui not built", http.StatusNotFound)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, index)
	})
}
