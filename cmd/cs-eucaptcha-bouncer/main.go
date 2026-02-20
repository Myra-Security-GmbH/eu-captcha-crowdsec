/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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

	crowdsec "github.com/Myra-Security-GmbH/eu-captcha-crowdsec"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := crowdsec.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	bouncer, err := crowdsec.NewBouncer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create bouncer: %v\n", err)
		os.Exit(1)
	}

	lapiClient, err := crowdsec.NewLAPIClient(cfg.CrowdSec, bouncer.Cache())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create lapi client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start LAPI polling in background.
	go lapiClient.Run(ctx)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      bouncer,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown", "err", err)
		}
	}()

	slog.Info("bouncer starting",
		"listen", cfg.ListenAddr,
		"upstream", cfg.UpstreamURL,
	)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	slog.Info("bouncer stopped")
}
