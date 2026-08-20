package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeELF(n int) []byte {
	b := make([]byte, n)
	copy(b, "\x7fELF")
	for i := 4; i < n; i++ {
		b[i] = byte(i)
	}
	return b
}

func TestDefaultURL(t *testing.T) {
	url := DefaultURL()
	if !strings.Contains(url, "github.com/jdbnet/opnsense-sftp/releases/latest/download/") {
		t.Fatalf("unexpected default url: %s", url)
	}
}

func TestSkip(t *testing.T) {
	if Skip(Config{Enabled: false}, "1.0.0") != "disabled" {
		t.Fatal("expected disabled")
	}
	if Skip(Config{Enabled: true}, "dev") != "dev build" {
		t.Fatal("expected dev build")
	}
	if Skip(Config{Enabled: true, AllowDev: true}, "dev") != "" {
		t.Fatal("allow_dev should run")
	}
	t.Setenv("OPNSENSE_SFTP_NO_UPDATE", "1")
	if Skip(Config{Enabled: true}, "1.0.0") != "OPNSENSE_SFTP_NO_UPDATE" {
		t.Fatal("expected env skip")
	}
}

func TestCheckSkipsWhenChecksumMatches(t *testing.T) {
	minBytes = 8
	t.Cleanup(func() { minBytes = 1 << 20 })

	bin := fakeELF(64)
	sum := sha256.Sum256(bin)
	mux := http.NewServeMux()
	mux.HandleFunc("/bin.sha256", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(hex.EncodeToString(sum[:])))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	exe := filepath.Join(t.TempDir(), "opnsense-sftp")
	if err := os.WriteFile(exe, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	lookExe = func() (string, error) { return exe, nil }
	t.Cleanup(func() { lookExe = currentExe })

	ok, err := Check(context.Background(), Config{Enabled: true, URL: srv.URL + "/bin", AllowDev: true}, "1.0.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("matching checksum should not replace")
	}
}

func TestCheckReplacesOnChecksumChange(t *testing.T) {
	minBytes = 8
	t.Cleanup(func() { minBytes = 1 << 20 })

	oldBin := fakeELF(64)
	newBin := fakeELF(96)
	newSum := sha256.Sum256(newBin)

	mux := http.NewServeMux()
	mux.HandleFunc("/opnsense-sftp-amd64", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(newBin)
	})
	mux.HandleFunc("/opnsense-sftp-amd64.sha256", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(hex.EncodeToString(newSum[:]) + "  opnsense-sftp-amd64\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	exe := filepath.Join(dir, "opnsense-sftp")
	if err := os.WriteFile(exe, oldBin, 0o755); err != nil {
		t.Fatal(err)
	}

	lookExe = func() (string, error) { return exe, nil }
	t.Cleanup(func() { lookExe = currentExe })

	ok, err := Check(context.Background(), Config{Enabled: true, URL: srv.URL + "/opnsense-sftp-amd64", AllowDev: true}, "1.0.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected replace")
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBin) {
		t.Fatal("binary not replaced")
	}
}

func TestReplaceSameHashIsNoop(t *testing.T) {
	minBytes = 8
	t.Cleanup(func() { minBytes = 1 << 20 })

	bin := fakeELF(64)
	sum := sha256.Sum256(bin)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bin)
	}))
	t.Cleanup(srv.Close)

	exe := filepath.Join(t.TempDir(), "opnsense-sftp")
	if err := os.WriteFile(exe, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err := replace(context.Background(), srv.URL, exe, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("same hash should not replace")
	}
}

func TestDownloadRejectsNonELF(t *testing.T) {
	minBytes = 8
	t.Cleanup(func() { minBytes = 1 << 20 })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not a binary</html>"))
	}))
	t.Cleanup(srv.Close)

	dest := filepath.Join(t.TempDir(), "opnsense-sftp.new")
	if _, err := download(context.Background(), srv.URL, dest); err == nil {
		t.Fatal("expected reject")
	}
}
