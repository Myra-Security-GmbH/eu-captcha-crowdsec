/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all bouncer configuration.
type Config struct {
	// ListenAddr is the address the bouncer listens on (e.g. "0.0.0.0:8080").
	ListenAddr string `yaml:"listen_addr"`

	// UpstreamURL is the backend to proxy to when a request is allowed.
	UpstreamURL string `yaml:"upstream_url"`

	// CrowdSec contains settings for the CrowdSec Local API.
	CrowdSec CrowdSecConfig `yaml:"crowdsec"`

	// EuCaptcha contains the EU CAPTCHA sitekey and secret.
	EuCaptcha EuCaptchaConfig `yaml:"eu_captcha"`

	// Session contains settings for the HMAC-signed session cookie.
	Session SessionConfig `yaml:"session"`

	// TrustedProxies is the list of CIDR ranges whose X-Forwarded-For header is trusted.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// CrowdSecConfig contains CrowdSec LAPI connection settings.
type CrowdSecConfig struct {
	// LAPIURL is the base URL of the CrowdSec LAPI (e.g. "http://localhost:8080").
	LAPIURL string `yaml:"lapi_url"`

	// APIKey is the bouncer API key registered in CrowdSec.
	APIKey string `yaml:"api_key"`

	// UpdateInterval is how often to poll the LAPI for decision updates (e.g. "10s").
	UpdateInterval string `yaml:"update_interval"`
}

// EuCaptchaConfig contains EU CAPTCHA credentials.
type EuCaptchaConfig struct {
	// Sitekey is the public sitekey shown in the widget.
	Sitekey string `yaml:"sitekey"`

	// Secret is the private secret used for server-side verification.
	Secret string `yaml:"secret"`

	// VerifyURL is the EU CAPTCHA verification endpoint.
	// Defaults to "https://api.eu-captcha.eu/v1/verify".
	VerifyURL string `yaml:"verify_url"`
}

// SessionConfig contains HMAC session cookie settings.
type SessionConfig struct {
	// Secret is the HMAC signing key (at least 32 random bytes, hex-encoded).
	Secret string `yaml:"secret"`

	// CookieName is the name of the session cookie. Defaults to "__eucaptcha_pass".
	CookieName string `yaml:"cookie_name"`

	// TTL is how long a verified session is valid (e.g. "1h"). Defaults to "1h".
	TTL string `yaml:"ttl"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Apply defaults.
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if cfg.CrowdSec.LAPIURL == "" {
		cfg.CrowdSec.LAPIURL = "http://localhost:8080"
	}
	if cfg.CrowdSec.UpdateInterval == "" {
		cfg.CrowdSec.UpdateInterval = "10s"
	}
	if cfg.EuCaptcha.VerifyURL == "" {
		cfg.EuCaptcha.VerifyURL = "https://api.eu-captcha.eu/v1/verify"
	}
	if cfg.Session.CookieName == "" {
		cfg.Session.CookieName = "__eucaptcha_pass"
	}
	if cfg.Session.TTL == "" {
		cfg.Session.TTL = "1h"
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validateConfig(cfg *Config) error {
	if cfg.UpstreamURL == "" {
		return fmt.Errorf("upstream_url is required")
	}
	if cfg.CrowdSec.APIKey == "" {
		return fmt.Errorf("crowdsec.api_key is required")
	}
	if cfg.EuCaptcha.Sitekey == "" {
		return fmt.Errorf("eu_captcha.sitekey is required")
	}
	if cfg.EuCaptcha.Secret == "" {
		return fmt.Errorf("eu_captcha.secret is required")
	}
	if cfg.Session.Secret == "" {
		return fmt.Errorf("session.secret is required (generate with: openssl rand -hex 32)")
	}
	return nil
}
