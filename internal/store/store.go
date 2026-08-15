package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	SQL  *sql.DB
	Path string
}

func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}
	path := filepath.Join(dataDir, "state.db")
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	db := &DB{SQL: sqlDB, Path: path}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.SQL.Close()
}

func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			totp_secret TEXT,
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS opnsense_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			identifier TEXT NOT NULL UNIQUE,
			ssh_key_id TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			last_backup TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key_id TEXT NOT NULL UNIQUE,
			instance_id INTEGER NOT NULL,
			public_key TEXT NOT NULL,
			private_key_path TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(instance_id) REFERENCES opnsense_instances(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			instance_id INTEGER NOT NULL,
			filename TEXT NOT NULL,
			file_path TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			uploaded_at TEXT NOT NULL,
			FOREIGN KEY(instance_id) REFERENCES opnsense_instances(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS backup_prune_settings (
			id INTEGER PRIMARY KEY,
			enabled INTEGER NOT NULL DEFAULT 0,
			scope_type TEXT NOT NULL DEFAULT 'all',
			scope_instance_id INTEGER,
			keep_days INTEGER,
			keep_count INTEGER,
			interval_seconds INTEGER NOT NULL DEFAULT 86400,
			last_run_at TEXT,
			updated_at TEXT,
			FOREIGN KEY(scope_instance_id) REFERENCES opnsense_instances(id) ON DELETE SET NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.SQL.Exec(s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	_, err := db.SQL.Exec(`
		INSERT INTO backup_prune_settings (id, enabled, scope_type, interval_seconds)
		VALUES (1, 0, 'all', 86400)
		ON CONFLICT(id) DO NOTHING`)
	return err
}

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	IsAdmin      bool   `json:"is_admin"`
	TOTPSecret   string `json:"-"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	CreatedAt    string `json:"created_at"`
}

type Instance struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Identifier  string  `json:"identifier"`
	SSHKeyID    string  `json:"ssh_key_id"`
	Description string  `json:"description"`
	LastBackup  *string `json:"last_backup"`
	CreatedAt   string  `json:"created_at"`
}

type SSHKey struct {
	ID             int64  `json:"id"`
	KeyID          string `json:"key_id"`
	InstanceID     int64  `json:"instance_id"`
	PublicKey      string `json:"public_key"`
	PrivateKeyPath string `json:"private_key_path"`
	CreatedAt      string `json:"created_at"`
}

type Backup struct {
	ID                 int64  `json:"id"`
	InstanceID         int64  `json:"instance_id"`
	Filename           string `json:"filename"`
	FilePath           string `json:"file_path"`
	FileSize           int64  `json:"file_size"`
	UploadedAt         string `json:"uploaded_at"`
	InstanceName       string `json:"instance_name,omitempty"`
	InstanceIdentifier string `json:"instance_identifier,omitempty"`
}

type PruneSettings struct {
	ID               int64   `json:"id"`
	Enabled          bool    `json:"enabled"`
	ScopeType        string  `json:"scope_type"`
	ScopeInstanceID  *int64  `json:"scope_instance_id"`
	KeepDays         *int    `json:"keep_days"`
	KeepCount        *int    `json:"keep_count"`
	IntervalSeconds  int     `json:"interval_seconds"`
	LastRunAt        *string `json:"last_run_at"`
	UpdatedAt        *string `json:"updated_at"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var isAdmin, totpEnabled int
	var totpSecret sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &isAdmin, &totpSecret, &totpEnabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.TOTPEnabled = totpEnabled != 0
	if totpSecret.Valid {
		u.TOTPSecret = totpSecret.String
	}
	return &u, nil
}

func (db *DB) CountUsers() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (db *DB) CreateUser(username, passwordHash string, isAdmin bool) (*User, error) {
	admin := 0
	if isAdmin {
		admin = 1
	}
	now := nowRFC3339()
	res, err := db.SQL.Exec(
		`INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)`,
		username, passwordHash, admin, now,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, PasswordHash: passwordHash, IsAdmin: isAdmin, CreatedAt: now}, nil
}

func (db *DB) GetUserByUsername(username string) (*User, error) {
	return scanUser(db.SQL.QueryRow(
		`SELECT id, username, password_hash, is_admin, totp_secret, totp_enabled, created_at FROM users WHERE username = ?`,
		username,
	))
}

func (db *DB) GetUserByID(id int64) (*User, error) {
	return scanUser(db.SQL.QueryRow(
		`SELECT id, username, password_hash, is_admin, totp_secret, totp_enabled, created_at FROM users WHERE id = ?`,
		id,
	))
}

func (db *DB) ListUsers() ([]User, error) {
	rows, err := db.SQL.Query(`SELECT id, username, password_hash, is_admin, totp_secret, totp_enabled, created_at FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (db *DB) UpdateUsername(userID int64, username string) error {
	_, err := db.SQL.Exec(`UPDATE users SET username = ? WHERE id = ?`, username, userID)
	return err
}

func (db *DB) UpdatePassword(userID int64, passwordHash string) error {
	_, err := db.SQL.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID)
	return err
}

func (db *DB) UpdateTOTP(userID int64, secret *string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := db.SQL.Exec(`UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, secret, en, userID)
	return err
}

func (db *DB) UpdateAdmin(userID int64, isAdmin bool) error {
	admin := 0
	if isAdmin {
		admin = 1
	}
	_, err := db.SQL.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, admin, userID)
	return err
}

func (db *DB) DeleteUser(userID int64) error {
	_, err := db.SQL.Exec(`DELETE FROM users WHERE id = ?`, userID)
	return err
}

func (db *DB) CreateSession(userID int64, tokenHash, expiresAt string) error {
	_, err := db.SQL.Exec(`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`, userID, tokenHash, expiresAt)
	return err
}

func (db *DB) GetSessionUserID(tokenHash string) (int64, string, error) {
	var userID int64
	var expires string
	err := db.SQL.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, tokenHash).Scan(&userID, &expires)
	return userID, expires, err
}

func (db *DB) DeleteSession(tokenHash string) error {
	_, err := db.SQL.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func scanInstance(row interface{ Scan(...any) error }) (*Instance, error) {
	var inst Instance
	var lastBackup sql.NullString
	if err := row.Scan(&inst.ID, &inst.Name, &inst.Identifier, &inst.SSHKeyID, &inst.Description, &lastBackup, &inst.CreatedAt); err != nil {
		return nil, err
	}
	if lastBackup.Valid {
		inst.LastBackup = &lastBackup.String
	}
	return &inst, nil
}

func (db *DB) CreateInstance(name, identifier, sshKeyID, description string) (*Instance, error) {
	now := nowRFC3339()
	res, err := db.SQL.Exec(
		`INSERT INTO opnsense_instances (name, identifier, ssh_key_id, description, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, identifier, sshKeyID, description, now,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Instance{ID: id, Name: name, Identifier: identifier, SSHKeyID: sshKeyID, Description: description, CreatedAt: now}, nil
}

func (db *DB) GetInstanceByID(id int64) (*Instance, error) {
	return scanInstance(db.SQL.QueryRow(
		`SELECT id, name, identifier, ssh_key_id, description, last_backup, created_at FROM opnsense_instances WHERE id = ?`, id,
	))
}

func (db *DB) GetInstanceByIdentifier(identifier string) (*Instance, error) {
	return scanInstance(db.SQL.QueryRow(
		`SELECT id, name, identifier, ssh_key_id, description, last_backup, created_at FROM opnsense_instances WHERE identifier = ?`, identifier,
	))
}

func (db *DB) ListInstances() ([]Instance, error) {
	rows, err := db.SQL.Query(`SELECT id, name, identifier, ssh_key_id, description, last_backup, created_at FROM opnsense_instances ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		inst, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inst)
	}
	return out, rows.Err()
}

func (db *DB) CountInstances() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM opnsense_instances`).Scan(&n)
	return n, err
}

func (db *DB) SaveSSHKey(keyID string, instanceID int64, publicKey, privateKeyPath string) error {
	_, err := db.SQL.Exec(
		`INSERT INTO ssh_keys (key_id, instance_id, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)`,
		keyID, instanceID, publicKey, privateKeyPath, nowRFC3339(),
	)
	return err
}

func (db *DB) GetSSHKeyByKeyID(keyID string) (*SSHKey, error) {
	var k SSHKey
	err := db.SQL.QueryRow(
		`SELECT id, key_id, instance_id, public_key, private_key_path, created_at FROM ssh_keys WHERE key_id = ?`, keyID,
	).Scan(&k.ID, &k.KeyID, &k.InstanceID, &k.PublicKey, &k.PrivateKeyPath, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (db *DB) RecordBackup(instanceID int64, filename, filePath string, fileSize int64) error {
	now := nowRFC3339()
	tx, err := db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO backups (instance_id, filename, file_path, file_size, uploaded_at) VALUES (?, ?, ?, ?, ?)`,
		instanceID, filename, filePath, fileSize, now,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE opnsense_instances SET last_backup = ? WHERE id = ?`, now, instanceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) GetBackupsForInstance(instanceID int64) ([]Backup, error) {
	rows, err := db.SQL.Query(
		`SELECT id, instance_id, filename, file_path, file_size, uploaded_at FROM backups WHERE instance_id = ? ORDER BY uploaded_at DESC`,
		instanceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBackups(rows)
}

func (db *DB) ListBackups(instanceID *int64, limit, offset int) ([]Backup, int, error) {
	var total int
	var rows *sql.Rows
	var err error
	if instanceID != nil {
		err = db.SQL.QueryRow(`SELECT COUNT(*) FROM backups WHERE instance_id = ?`, *instanceID).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
		rows, err = db.SQL.Query(`
			SELECT b.id, b.instance_id, b.filename, b.file_path, b.file_size, b.uploaded_at, o.name, o.identifier
			FROM backups b JOIN opnsense_instances o ON b.instance_id = o.id
			WHERE b.instance_id = ?
			ORDER BY b.uploaded_at DESC LIMIT ? OFFSET ?`, *instanceID, limit, offset)
	} else {
		err = db.SQL.QueryRow(`SELECT COUNT(*) FROM backups`).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
		rows, err = db.SQL.Query(`
			SELECT b.id, b.instance_id, b.filename, b.file_path, b.file_size, b.uploaded_at, o.name, o.identifier
			FROM backups b JOIN opnsense_instances o ON b.instance_id = o.id
			ORDER BY b.uploaded_at DESC LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	backups, err := scanBackupsWithInstance(rows)
	return backups, total, err
}

func scanBackups(rows *sql.Rows) ([]Backup, error) {
	var out []Backup
	for rows.Next() {
		var b Backup
		if err := rows.Scan(&b.ID, &b.InstanceID, &b.Filename, &b.FilePath, &b.FileSize, &b.UploadedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanBackupsWithInstance(rows *sql.Rows) ([]Backup, error) {
	var out []Backup
	for rows.Next() {
		var b Backup
		if err := rows.Scan(&b.ID, &b.InstanceID, &b.Filename, &b.FilePath, &b.FileSize, &b.UploadedAt, &b.InstanceName, &b.InstanceIdentifier); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) GetBackupByID(id int64) (*Backup, error) {
	var b Backup
	err := db.SQL.QueryRow(`
		SELECT b.id, b.instance_id, b.filename, b.file_path, b.file_size, b.uploaded_at, o.name, o.identifier
		FROM backups b JOIN opnsense_instances o ON b.instance_id = o.id WHERE b.id = ?`, id,
	).Scan(&b.ID, &b.InstanceID, &b.Filename, &b.FilePath, &b.FileSize, &b.UploadedAt, &b.InstanceName, &b.InstanceIdentifier)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (db *DB) DeleteBackup(id int64) error {
	_, err := db.SQL.Exec(`DELETE FROM backups WHERE id = ?`, id)
	return err
}

func (db *DB) DeleteBackupsByIDs(ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	query := `DELETE FROM backups WHERE id IN (`
	args := make([]any, len(ids))
	for i, id := range ids {
		if i > 0 {
			query += ","
		}
		query += "?"
		args[i] = id
	}
	query += ")"
	res, err := db.SQL.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (db *DB) CountBackups() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM backups`).Scan(&n)
	return n, err
}

func (db *DB) TotalBackupSize() (int64, error) {
	var n sql.NullInt64
	err := db.SQL.QueryRow(`SELECT COALESCE(SUM(file_size), 0) FROM backups`).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n.Int64, nil
}

func (db *DB) GetPruneSettings() (*PruneSettings, error) {
	var s PruneSettings
	var enabled int
	var scopeInst sql.NullInt64
	var keepDays, keepCount sql.NullInt64
	var lastRun, updated sql.NullString
	err := db.SQL.QueryRow(`SELECT id, enabled, scope_type, scope_instance_id, keep_days, keep_count, interval_seconds, last_run_at, updated_at FROM backup_prune_settings WHERE id = 1`).
		Scan(&s.ID, &enabled, &s.ScopeType, &scopeInst, &keepDays, &keepCount, &s.IntervalSeconds, &lastRun, &updated)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled != 0
	if scopeInst.Valid {
		s.ScopeInstanceID = &scopeInst.Int64
	}
	if keepDays.Valid {
		v := int(keepDays.Int64)
		s.KeepDays = &v
	}
	if keepCount.Valid {
		v := int(keepCount.Int64)
		s.KeepCount = &v
	}
	if lastRun.Valid {
		s.LastRunAt = &lastRun.String
	}
	if updated.Valid {
		s.UpdatedAt = &updated.String
	}
	return &s, nil
}

func (db *DB) UpsertPruneSettings(s PruneSettings) error {
	en := 0
	if s.Enabled {
		en = 1
	}
	now := nowRFC3339()
	_, err := db.SQL.Exec(`
		INSERT INTO backup_prune_settings (id, enabled, scope_type, scope_instance_id, keep_days, keep_count, interval_seconds, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			enabled = excluded.enabled,
			scope_type = excluded.scope_type,
			scope_instance_id = excluded.scope_instance_id,
			keep_days = excluded.keep_days,
			keep_count = excluded.keep_count,
			interval_seconds = excluded.interval_seconds,
			updated_at = excluded.updated_at`,
		en, s.ScopeType, s.ScopeInstanceID, s.KeepDays, s.KeepCount, s.IntervalSeconds, now,
	)
	return err
}

func (db *DB) SetPruneLastRun(at string) error {
	_, err := db.SQL.Exec(`UPDATE backup_prune_settings SET last_run_at = ? WHERE id = 1`, at)
	return err
}
