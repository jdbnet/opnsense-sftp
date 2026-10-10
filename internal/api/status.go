package api

import (
	"net/http"
	"time"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
)

const appName = "opnsense-sftp"

type healthResponse struct {
	App     string `json:"app"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

type backupJob struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	Target              string  `json:"target"`
	Enabled             bool    `json:"enabled"`
	LastRunAt           *string `json:"last_run_at"`
	LastStatus          string  `json:"last_status"`
	LastSuccessAt       *string `json:"last_success_at"`
	LastDurationSeconds *int64  `json:"last_duration_seconds"`
	LastSizeBytes       *int64  `json:"last_size_bytes"`
	LastError           *string `json:"last_error"`
	NextRunAt           *string `json:"next_run_at"`
	Stale               bool    `json:"stale"`
}

type backupStatusResponse struct {
	App         string      `json:"app"`
	Version     string      `json:"version"`
	GeneratedAt string      `json:"generated_at"`
	Overall     string      `json:"overall"`
	Jobs        []backupJob `json:"jobs"`
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		App:     appName,
		Version: s.version,
		Status:  "ok",
	})
}

func (s *Server) backupStatus(w http.ResponseWriter, r *http.Request) {
	resp, err := s.buildBackupStatus(time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) staleAfter() time.Duration {
	if s.cfg != nil && s.cfg.StaleAfter.Duration > 0 {
		return s.cfg.StaleAfter.Duration
	}
	return 48 * time.Hour
}

func (s *Server) buildBackupStatus(now time.Time) (backupStatusResponse, error) {
	rows, err := s.db.ListInstanceBackupStatus()
	if err != nil {
		return backupStatusResponse{}, err
	}
	after := s.staleAfter()
	jobs := make([]backupJob, 0, len(rows))
	for _, row := range rows {
		jobs = append(jobs, jobFromInstance(row, now, after))
	}
	return backupStatusResponse{
		App:         appName,
		Version:     s.version,
		GeneratedAt: now.Format(time.RFC3339),
		Overall:     overallStatus(jobs),
		Jobs:        jobs,
	}, nil
}

// jobFromInstance maps one firewall instance to a status job.
// A received backup is success. The app does not record failed, running, or
// partial pushes, duration, or the next scheduled push.
func jobFromInstance(row store.InstanceBackupStatus, now time.Time, after time.Duration) backupJob {
	job := backupJob{
		ID:         row.Identifier,
		Name:       row.Name,
		Target:     row.Identifier,
		Enabled:    true,
		LastStatus: "never_run",
	}
	when := row.LastUploaded
	if when == nil || *when == "" {
		when = row.LastBackup
	}
	if when == nil || *when == "" {
		return job
	}
	job.LastStatus = "success"
	job.LastRunAt = when
	job.LastSuccessAt = when
	job.LastSizeBytes = row.LastSize
	job.Stale = backupStale(parseRFC3339(when), now, after)
	return job
}

func backupStale(lastSuccess *time.Time, now time.Time, after time.Duration) bool {
	if lastSuccess == nil {
		return false
	}
	if after <= 0 {
		after = 48 * time.Hour
	}
	return now.Sub(*lastSuccess) > after
}

func overallStatus(jobs []backupJob) string {
	enabled := 0
	failing := false
	warning := false
	for _, job := range jobs {
		if !job.Enabled {
			continue
		}
		enabled++
		if job.LastStatus == "failed" {
			failing = true
		}
		if job.Stale || job.LastStatus == "partial" || job.LastStatus == "never_run" {
			warning = true
		}
	}
	if enabled == 0 {
		return "unknown"
	}
	if failing {
		return "failing"
	}
	if warning {
		return "warning"
	}
	return "ok"
}

func parseRFC3339(value *string) *time.Time {
	if value == nil || *value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *value)
	if err != nil {
		return nil
	}
	return &parsed
}
