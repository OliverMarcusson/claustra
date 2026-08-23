package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olivermarcusson/claustra/internal/config"
	"github.com/olivermarcusson/claustra/internal/security"
	"github.com/olivermarcusson/claustra/internal/server"
	"github.com/olivermarcusson/claustra/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "claustra:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if len(os.Args) != 3 {
			return errors.New("usage: claustra keygen <path>")
		}
		return security.GenerateRSAKey(os.Args[2])
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err = st.Migrate(ctx); err != nil {
		return err
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		has, err := st.HasAdmin(ctx)
		if err != nil {
			return err
		}
		if has {
			return errors.New("an administrator already exists")
		}
		token, err := security.RandomToken(32)
		if err != nil {
			return err
		}
		if err = st.PutBootstrapToken(ctx, store.HashSecret(token), time.Now().Add(15*time.Minute)); err != nil {
			return err
		}
		fmt.Printf("%s/register?bootstrap=%s\n", cfg.Issuer, token)
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "invalidate-restored-state" {
		if err = st.InvalidateEphemeralState(ctx); err != nil {
			return err
		}
		fmt.Println("restored sessions, codes, tokens, and pending recoveries invalidated")
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		return errors.New("usage: claustra [serve|bootstrap|invalidate-restored-state|keygen <path>]")
	}
	key, keyID, err := security.LoadRSAKey(cfg.SigningKeyFile)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var previous []server.PublicSigningKey
	for _, path := range cfg.PreviousSigningKeyFiles {
		old, oldID, loadErr := security.LoadRSAKey(path)
		if loadErr != nil {
			return fmt.Errorf("load previous signing key %s: %w", path, loadErr)
		}
		previous = append(previous, server.PublicSigningKey{Key: &old.PublicKey, KeyID: oldID})
	}
	app, err := server.New(cfg, st, key, keyID, previous, logger)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	go maintenance(ctx, st, logger)
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	logger.Info("starting Claustra", "listen", cfg.ListenAddr, "issuer", cfg.Issuer, "rp_id", cfg.RPID, "signing_key_id", keyID)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func maintenance(ctx context.Context, st *store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	run := func() {
		workCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := st.FinalizeRecoveries(workCtx); err != nil {
			logger.Error("finalize recoveries", "error", err)
		}
		if err := st.FinalizeDeletions(workCtx); err != nil {
			logger.Error("finalize deletions", "error", err)
		}
		if err := st.Cleanup(workCtx); err != nil {
			logger.Error("cleanup", "error", err)
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
