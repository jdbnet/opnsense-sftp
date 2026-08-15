package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const defaultBase = "https://apps.jdbnet.co.uk"

var (
	minBytes   int64 = 1 << 20
	httpClient       = &http.Client{Timeout: 2 * time.Minute}
	lookExe          = currentExe
)

type Config struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	AllowDev bool   `yaml:"allow_dev"`
}

func DefaultURL() string {
	asset := "opnsense-sftp-amd64"
	if runtime.GOARCH == "arm64" {
		asset = "opnsense-sftp-arm64"
	}
	return defaultBase + "/" + asset
}

func Skip(cfg Config, version string) string {
	if os.Getenv("OPNSENSE_SFTP_NO_UPDATE") != "" {
		return "OPNSENSE_SFTP_NO_UPDATE"
	}
	if !cfg.Enabled {
		return "disabled"
	}
	if version == "dev" && !cfg.AllowDev {
		return "dev build"
	}
	return ""
}

func ResolveURL(cfg Config) string {
	if strings.TrimSpace(cfg.URL) != "" {
		return strings.TrimSpace(cfg.URL)
	}
	return DefaultURL()
}

// Check downloads a newer binary over the current executable when the published
// checksum (or ETag) differs. On success with a replace, call Restart.
func Check(ctx context.Context, cfg Config, version, dataDir string) (replaced bool, err error) {
	if reason := Skip(cfg, version); reason != "" {
		return false, nil
	}
	exe, err := lookExe()
	if err != nil {
		return false, fmt.Errorf("executable: %w", err)
	}
	url := ResolveURL(cfg)
	localSum, err := fileSHA256(exe)
	if err != nil {
		return false, err
	}
	remoteSum, hasSum, err := fetchChecksum(ctx, url+".sha256")
	if err != nil {
		return false, err
	}
	etagPath := filepath.Join(dataDir, "update.etag")
	if hasSum {
		if strings.EqualFold(remoteSum, localSum) {
			return false, nil
		}
		return replace(ctx, url, exe, remoteSum)
	}
	etag, err := headETag(ctx, url)
	if err != nil {
		return false, err
	}
	if etag != "" {
		if prev, _ := os.ReadFile(etagPath); strings.TrimSpace(string(prev)) == etag {
			return false, nil
		}
	}
	ok, err := replace(ctx, url, exe, "")
	if err != nil {
		return false, err
	}
	if etag != "" {
		_ = os.WriteFile(etagPath, []byte(etag+"\n"), 0o644)
	}
	return ok, nil
}

func Restart() error {
	exe, err := currentExe()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}

func currentExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func replace(ctx context.Context, url, exe, wantSum string) (bool, error) {
	tmp := exe + ".new"
	sum, err := download(ctx, url, tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if wantSum != "" && !strings.EqualFold(sum, wantSum) {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("checksum mismatch after download")
	}
	cur, err := fileSHA256(exe)
	if err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if strings.EqualFold(sum, cur) {
		_ = os.Remove(tmp)
		return false, nil
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("replace binary: %w", err)
	}
	return true, nil
}

func download(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "opnsense-sftp")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n < minBytes {
		return "", fmt.Errorf("download too small (%d bytes)", n)
	}
	buf := make([]byte, 4)
	f, err = os.Open(dest)
	if err != nil {
		return "", err
	}
	_, err = io.ReadFull(f, buf)
	_ = f.Close()
	if err != nil {
		return "", err
	}
	if string(buf) != "\x7fELF" {
		return "", fmt.Errorf("download is not a linux binary")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fetchChecksum(ctx context.Context, url string) (sum string, ok bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "opnsense-sftp")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("checksum: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false, err
	}
	sum = strings.TrimSpace(string(body))
	if i := strings.IndexAny(sum, " \t"); i > 0 {
		sum = sum[:i]
	}
	if len(sum) != 64 {
		return "", false, fmt.Errorf("checksum: invalid sha256")
	}
	return sum, true, nil
}

func headETag(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "opnsense-sftp")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("head: %s", resp.Status)
	}
	return strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
