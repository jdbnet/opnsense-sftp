package store

import (
	"database/sql"
	"fmt"
)

const (
	APIKeySourceUI     = "ui"
	APIKeySourceConfig = "config"
)

// APIKey is a read-only status API credential. KeyHash is never serialised.
type APIKey struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	Prefix    string  `json:"prefix"`
	KeyHash   string  `json:"-"`
	Source    string  `json:"source"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

type InstanceBackupStatus struct {
	Instance
	LastSize     *int64
	LastUploaded *string
}

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	var revoked sql.NullString
	if err := row.Scan(&k.ID, &k.Name, &k.Prefix, &k.KeyHash, &k.Source, &k.CreatedAt, &revoked); err != nil {
		return nil, err
	}
	if revoked.Valid {
		k.RevokedAt = &revoked.String
	}
	return &k, nil
}

func (db *DB) CreateAPIKey(name, prefix, hash, source string) (*APIKey, error) {
	if source == "" {
		source = APIKeySourceUI
	}
	now := nowRFC3339()
	res, err := db.SQL.Exec(
		`INSERT INTO api_keys (name, key_prefix, key_hash, source, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, prefix, hash, source, now,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return db.GetAPIKey(id)
}

func (db *DB) GetAPIKey(id int64) (*APIKey, error) {
	return scanAPIKey(db.SQL.QueryRow(
		`SELECT id, name, key_prefix, key_hash, source, created_at, revoked_at FROM api_keys WHERE id = ?`,
		id,
	))
}

func (db *DB) GetActiveAPIKeyByHash(hash string) (*APIKey, error) {
	return scanAPIKey(db.SQL.QueryRow(
		`SELECT id, name, key_prefix, key_hash, source, created_at, revoked_at
		 FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`,
		hash,
	))
}

func (db *DB) ListActiveAPIKeys() ([]APIKey, error) {
	rows, err := db.SQL.Query(
		`SELECT id, name, key_prefix, key_hash, source, created_at, revoked_at
		 FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC, id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (db *DB) RevokeAPIKey(id int64) error {
	_, err := db.SQL.Exec(`UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, nowRFC3339(), id)
	return err
}

// ConfigAPIKey is a plaintext credential supplied from config or the environment.
// Callers hash it before persistence.
type ConfigAPIKey struct {
	Name   string
	Prefix string
	Hash   string
}

// SyncConfigAPIKeys upserts configuration-sourced keys and revokes config keys
// that are no longer present. UI-created keys are left unchanged.
func (db *DB) SyncConfigAPIKeys(keys []ConfigAPIKey) error {
	tx, err := db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	keep := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k.Name == "" || k.Hash == "" {
			continue
		}
		keep[k.Name] = struct{}{}
		var id int64
		err := tx.QueryRow(
			`SELECT id FROM api_keys WHERE source = ? AND name = ?`,
			APIKeySourceConfig, k.Name,
		).Scan(&id)
		if err == sql.ErrNoRows {
			_, err = tx.Exec(
				`INSERT INTO api_keys (name, key_prefix, key_hash, source, created_at) VALUES (?, ?, ?, ?, ?)`,
				k.Name, k.Prefix, k.Hash, APIKeySourceConfig, nowRFC3339(),
			)
			if err != nil {
				return fmt.Errorf("api key %s: %w", k.Name, err)
			}
			continue
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`UPDATE api_keys SET key_prefix = ?, key_hash = ?, revoked_at = NULL WHERE id = ?`,
			k.Prefix, k.Hash, id,
		); err != nil {
			return fmt.Errorf("api key %s: %w", k.Name, err)
		}
	}

	rows, err := tx.Query(`SELECT id, name FROM api_keys WHERE source = ? AND revoked_at IS NULL`, APIKeySourceConfig)
	if err != nil {
		return err
	}
	var revoke []int64
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		if _, ok := keep[name]; !ok {
			revoke = append(revoke, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	now := nowRFC3339()
	for _, id := range revoke {
		if _, err := tx.Exec(`UPDATE api_keys SET revoked_at = ? WHERE id = ?`, now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListInstanceBackupStatus() ([]InstanceBackupStatus, error) {
	rows, err := db.SQL.Query(`
		SELECT i.id, i.name, i.identifier, i.ssh_key_id, i.description, i.last_backup, i.created_at,
			(SELECT b.file_size FROM backups b WHERE b.instance_id = i.id ORDER BY b.uploaded_at DESC, b.id DESC LIMIT 1),
			(SELECT b.uploaded_at FROM backups b WHERE b.instance_id = i.id ORDER BY b.uploaded_at DESC, b.id DESC LIMIT 1)
		FROM opnsense_instances i
		ORDER BY i.identifier ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstanceBackupStatus
	for rows.Next() {
		var row InstanceBackupStatus
		var lastBackup sql.NullString
		var size sql.NullInt64
		var uploaded sql.NullString
		if err := rows.Scan(
			&row.ID, &row.Name, &row.Identifier, &row.SSHKeyID, &row.Description, &lastBackup, &row.CreatedAt,
			&size, &uploaded,
		); err != nil {
			return nil, err
		}
		if lastBackup.Valid {
			v := lastBackup.String
			row.LastBackup = &v
		}
		if size.Valid {
			v := size.Int64
			row.LastSize = &v
		}
		if uploaded.Valid {
			v := uploaded.String
			row.LastUploaded = &v
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
