/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Decision is a single CrowdSec LAPI decision.
type Decision struct {
	ID       int64  `json:"id"`
	Value    string `json:"value"`    // IP or CIDR
	Type     string `json:"type"`     // "ban", "captcha", …
	Scope    string `json:"scope"`    // "ip", "range", …
	Duration string `json:"duration"` // e.g. "4h"
}

// streamResponse is the JSON body returned by /v1/decisions/stream.
type streamResponse struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

// LAPIClient polls the CrowdSec Local API for decision updates.
type LAPIClient struct {
	baseURL        string
	apiKey         string
	updateInterval time.Duration
	cache          *decisionCache
	httpClient     *http.Client
	startup        bool
}

// NewLAPIClient creates a new client and performs the initial blocking sync.
func NewLAPIClient(cfg CrowdSecConfig, cache *decisionCache) (*LAPIClient, error) {
	d, err := time.ParseDuration(cfg.UpdateInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid update_interval %q: %w", cfg.UpdateInterval, err)
	}

	c := &LAPIClient{
		baseURL:        strings.TrimRight(cfg.LAPIURL, "/"),
		apiKey:         cfg.APIKey,
		updateInterval: d,
		cache:          cache,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		startup:        true,
	}
	return c, nil
}

// Run polls the LAPI until ctx is cancelled. Call in a goroutine.
func (c *LAPIClient) Run(ctx context.Context) {
	ticker := time.NewTicker(c.updateInterval)
	defer ticker.Stop()

	// Poll immediately on start.
	c.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *LAPIClient) poll(ctx context.Context) {
	url := c.baseURL + "/v1/decisions/stream"
	if c.startup {
		url += "?startup=true"
		c.startup = false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Error("lapi: build request", "err", err)
		return
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Error("lapi: request failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No changes since last poll.
		return
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("lapi: unexpected status", "status", resp.StatusCode)
		return
	}

	var body streamResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		slog.Error("lapi: decode response", "err", err)
		return
	}

	c.cache.Apply(body.New, body.Deleted)

	if len(body.New) > 0 || len(body.Deleted) > 0 {
		slog.Info("lapi: decisions updated",
			"added", len(body.New),
			"deleted", len(body.Deleted),
		)
	}
}
