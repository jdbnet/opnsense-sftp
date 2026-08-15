package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName           = "opnsense_sftp_session"
	DefaultAdminUser     = "admin"
	DefaultAdminPassword = "changeme"
	sessionDuration      = 24 * time.Hour
	pendingTOTPDuration  = 5 * time.Minute
)

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	IsAdmin     bool   `json:"is_admin"`
	TOTPEnabled bool   `json:"totp_enabled"`
	CreatedAt   string `json:"created_at"`
}

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	User *User  `json:"user,omitempty"`
}

type contextKey int

const actorKey contextKey = 1

func ActorFrom(ctx context.Context) *Actor {
	a, _ := ctx.Value(actorKey).(*Actor)
	return a
}

func WithActor(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, actorKey, a)
}

type pendingTOTP struct {
	userID    int64
	expiresAt time.Time
}

type Service struct {
	db      *store.DB
	pending map[string]pendingTOTP
	mu      sync.Mutex
}

func New(db *store.DB) *Service {
	return &Service{db: db, pending: make(map[string]pendingTOTP)}
}

func (s *Service) BootstrapAdmin() (username string, created bool, err error) {
	n, err := s.db.CountUsers()
	if err != nil {
		return "", false, err
	}
	if n > 0 {
		return "", false, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(DefaultAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", false, err
	}
	if _, err := s.db.CreateUser(DefaultAdminUser, string(hash), true); err != nil {
		return "", false, err
	}
	return DefaultAdminUser, true, nil
}

func (s *Service) HasUsers() (bool, error) {
	n, err := s.db.CountUsers()
	return n > 0, err
}

func toUser(u *store.User) *User {
	return &User{
		ID:          u.ID,
		Username:    u.Username,
		IsAdmin:     u.IsAdmin,
		TOTPEnabled: u.TOTPEnabled,
		CreatedAt:   u.CreatedAt,
	}
}

func (s *Service) Authenticate(username, password string) (*store.User, error) {
	u, err := s.db.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return u, nil
}

func (s *Service) CreatePendingTOTP(userID int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupPendingLocked()
	s.pending[token] = pendingTOTP{userID: userID, expiresAt: time.Now().Add(pendingTOTPDuration)}
	return token, nil
}

func (s *Service) VerifyPendingTOTP(token, code string) (*store.User, error) {
	s.mu.Lock()
	p, ok := s.pending[token]
	if ok {
		delete(s.pending, token)
	}
	s.cleanupPendingLocked()
	s.mu.Unlock()
	if !ok || time.Now().After(p.expiresAt) {
		return nil, fmt.Errorf("invalid or expired pending token")
	}
	u, err := s.db.GetUserByID(p.userID)
	if err != nil {
		return nil, err
	}
	if !u.TOTPEnabled || u.TOTPSecret == "" {
		return nil, fmt.Errorf("totp not enabled")
	}
	if !totp.Validate(code, u.TOTPSecret) {
		return nil, fmt.Errorf("invalid totp code")
	}
	return u, nil
}

func (s *Service) cleanupPendingLocked() {
	now := time.Now()
	for k, v := range s.pending {
		if now.After(v.expiresAt) {
			delete(s.pending, k)
		}
	}
}

func (s *Service) CreateSession(userID int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().UTC().Add(sessionDuration).Format(time.RFC3339)
	if err := s.db.CreateSession(userID, hex.EncodeToString(sum[:]), expires); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) SessionUser(token string) (*store.User, error) {
	sum := sha256.Sum256([]byte(token))
	userID, expires, err := s.db.GetSessionUserID(hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil || time.Now().UTC().After(exp) {
		return nil, fmt.Errorf("session expired")
	}
	return s.db.GetUserByID(userID)
}

func (s *Service) DeleteSession(token string) error {
	sum := sha256.Sum256([]byte(token))
	return s.db.DeleteSession(hex.EncodeToString(sum[:]))
}

func (s *Service) CreateUser(username, password string, isAdmin bool) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u, err := s.db.CreateUser(username, string(hash), isAdmin)
	if err != nil {
		return nil, err
	}
	return toUser(u), nil
}

func (s *Service) ListUsers() ([]User, error) {
	users, err := s.db.ListUsers()
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(users))
	for _, u := range users {
		out = append(out, *toUser(&u))
	}
	return out, nil
}

func (s *Service) UpdateUsername(userID int64, username string) error {
	return s.db.UpdateUsername(userID, username)
}

func (s *Service) ChangePassword(userID int64, current, next string) error {
	if current == "" || next == "" {
		return fmt.Errorf("current and new password are required")
	}
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.UpdatePassword(userID, string(hash))
}

func (s *Service) SetPassword(userID int64, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.UpdatePassword(userID, string(hash))
}

func (s *Service) GenerateTOTPSecret(userID int64) (string, string, error) {
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return "", "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OPNsense SFTP",
		AccountName: u.Username,
	})
	if err != nil {
		return "", "", err
	}
	secret := key.Secret()
	if err := s.db.UpdateTOTP(userID, &secret, false); err != nil {
		return "", "", err
	}
	return secret, key.URL(), nil
}

func (s *Service) EnableTOTP(userID int64, code string) error {
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}
	if u.TOTPSecret == "" {
		return fmt.Errorf("generate totp secret first")
	}
	if !totp.Validate(code, u.TOTPSecret) {
		return fmt.Errorf("invalid totp code")
	}
	return s.db.UpdateTOTP(userID, &u.TOTPSecret, true)
}

func (s *Service) DisableTOTP(userID int64) error {
	return s.db.UpdateTOTP(userID, nil, false)
}

func (s *Service) ToggleAdmin(userID int64, isAdmin bool) error {
	return s.db.UpdateAdmin(userID, isAdmin)
}

func (s *Service) DeleteUser(userID int64) error {
	return s.db.DeleteUser(userID)
}

func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func SessionToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := SessionToken(r)
		if token == "" {
			writeUnauthorized(w)
			return
		}
		u, err := s.SessionUser(token)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		actor := &Actor{Type: "user", ID: u.Username, User: toUser(u)}
		next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
}

func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := ActorFrom(r.Context())
		if a == nil || a.User == nil || !a.User.IsAdmin {
			writeForbidden(w)
			return
		}
		next(w, r)
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}

func ToPublicUser(u *store.User) *User {
	if u == nil {
		return nil
	}
	return &User{
		ID:          u.ID,
		Username:    u.Username,
		IsAdmin:     u.IsAdmin,
		TOTPEnabled: u.TOTPEnabled,
		CreatedAt:   u.CreatedAt,
	}
}
