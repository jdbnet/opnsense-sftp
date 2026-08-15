package prune

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/config"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
)

type Result struct {
	DeletedBackups int `json:"deleted_backups"`
	DeletedFiles   int `json:"deleted_files"`
	SkippedFiles   int `json:"skipped_files"`
	Errors         int `json:"errors"`
}

type Service struct {
	db  *store.DB
	cfg *config.Config
}

func New(db *store.DB, cfg *config.Config) *Service {
	return &Service{db: db, cfg: cfg}
}

func Run(db *store.DB, scopeType string, scopeInstanceID *int64, keepDays, keepCount *int) (Result, error) {
	if (keepDays == nil && keepCount == nil) || (keepDays != nil && keepCount != nil) {
		return Result{}, fmt.Errorf("exactly one of keep_days or keep_count must be provided")
	}
	if scopeType != "all" && scopeType != "instance" {
		return Result{}, fmt.Errorf("scope_type must be 'all' or 'instance'")
	}

	var instances []store.Instance
	if scopeType == "instance" {
		if scopeInstanceID == nil {
			return Result{}, fmt.Errorf("scope_instance_id required for instance scope")
		}
		inst, err := db.GetInstanceByID(*scopeInstanceID)
		if err != nil {
			return Result{Errors: 1}, nil
		}
		instances = []store.Instance{*inst}
	} else {
		var err error
		instances, err = db.ListInstances()
		if err != nil {
			return Result{}, err
		}
	}

	var cutoff time.Time
	if keepDays != nil {
		cutoff = time.Now().Add(-time.Duration(*keepDays) * 24 * time.Hour)
	}

	var toDelete []store.Backup
	for _, inst := range instances {
		backups, err := db.GetBackupsForInstance(inst.ID)
		if err != nil {
			return Result{}, err
		}
		if keepDays != nil {
			for _, b := range backups {
				uploaded, err := time.Parse(time.RFC3339, b.UploadedAt)
				if err != nil || uploaded.Before(cutoff) {
					toDelete = append(toDelete, b)
				}
			}
		} else if keepCount != nil {
			if len(backups) > *keepCount {
				toDelete = append(toDelete, backups[*keepCount:]...)
			}
		}
	}

	if len(toDelete) == 0 {
		return Result{}, nil
	}

	var result Result
	var ids []int64
	for _, b := range toDelete {
		if err := os.Remove(b.FilePath); err != nil {
			if os.IsNotExist(err) {
				result.SkippedFiles++
			} else {
				result.SkippedFiles++
				result.Errors++
				slog.Error("prune delete file", "path", b.FilePath, "err", err)
			}
		} else {
			result.DeletedFiles++
		}
		ids = append(ids, b.ID)
	}
	n, err := db.DeleteBackupsByIDs(ids)
	if err != nil {
		return result, err
	}
	result.DeletedBackups = n
	return result, nil
}

func (s *Service) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			settings, err := s.db.GetPruneSettings()
			if err != nil {
				slog.Error("auto prune settings", "err", err)
				s.sleep(ctx, s.cfg.Prune.CheckInterval.Duration)
				continue
			}
			if !settings.Enabled {
				s.sleep(ctx, s.cfg.Prune.CheckInterval.Duration)
				continue
			}
			interval := time.Duration(settings.IntervalSeconds) * time.Second
			if settings.LastRunAt != nil {
				last, err := time.Parse(time.RFC3339, *settings.LastRunAt)
				if err == nil && time.Since(last) < interval {
					s.sleep(ctx, interval-time.Since(last))
					continue
				}
			}
			if settings.KeepDays == nil && settings.KeepCount == nil {
				s.sleep(ctx, interval)
				continue
			}
			result, err := Run(s.db, settings.ScopeType, settings.ScopeInstanceID, settings.KeepDays, settings.KeepCount)
			if err != nil {
				slog.Error("auto prune", "err", err)
			} else {
				slog.Info("auto prune completed", "deleted_backups", result.DeletedBackups, "deleted_files", result.DeletedFiles)
			}
			_ = s.db.SetPruneLastRun(time.Now().UTC().Format(time.RFC3339))
			s.sleep(ctx, interval)
		}
	}()
}

func (s *Service) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		d = time.Hour
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func EnsureBackupDir(backupsDir, identifier string) (string, error) {
	dir := filepath.Join(backupsDir, identifier)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
