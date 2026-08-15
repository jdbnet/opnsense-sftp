package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/api"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/auth"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/config"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/keys"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/prune"
	sftpsrv "git.jdbnet.co.uk/jamie/opnsense-sftp/internal/sftp"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/store"
	"git.jdbnet.co.uk/jamie/opnsense-sftp/internal/update"
)

var Version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(Version)
		return
	}

	configPath := "config.yaml"
	if args := flag.Args(); len(args) > 0 {
		configPath = args[0]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()})))
	if err := cfg.EnsureDirs(); err != nil {
		slog.Error("ensure dirs", "err", err)
		os.Exit(1)
	}

	updCtx, updCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	replaced, err := update.Check(updCtx, update.Config{
		Enabled:  cfg.Update.Enabled,
		URL:      cfg.Update.URL,
		AllowDev: cfg.Update.AllowDev,
	}, Version, cfg.DataDir)
	updCancel()
	if err != nil {
		slog.Warn("update check failed, continuing", "err", err)
	} else if replaced {
		slog.Info("installed newer binary, restarting")
		if err := update.Restart(); err != nil {
			slog.Error("restart after update", "err", err)
		}
	}

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	authSvc := auth.New(db)
	username, created, err := authSvc.BootstrapAdmin()
	if err != nil {
		slog.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}
	if created {
		slog.Warn("created admin account; change the password after first login", "username", username)
	}
	hasUsers, err := authSvc.HasUsers()
	if err != nil {
		slog.Error("users", "err", err)
		os.Exit(1)
	}

	keysMgr := keys.NewManager(cfg.KeysDir)
	sftpServer := sftpsrv.New(cfg.SFTP.Listen, cfg.BackupsDir, db, keysMgr)
	if err := sftpServer.Start(); err != nil {
		slog.Error("sftp", "err", err)
		os.Exit(1)
	}
	defer sftpServer.Stop()

	pruneSvc := prune.New(db, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pruneSvc.Start(ctx)

	srvAPI := api.New(cfg, authSvc, db, keysMgr, hasUsers, Version)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("http listening", "addr", cfg.Listen, "version", Version)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	cancel()
	shctx, shcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shcancel()
	_ = httpSrv.Shutdown(shctx)
}
