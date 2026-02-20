/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"embed"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

//go:embed templates/captcha.html
var templateFS embed.FS

// Bouncer is the core reverse proxy with CrowdSec decision enforcement.
type Bouncer struct {
	cfg      *Config
	cache    *decisionCache
	session  *sessionManager
	verifier *euCaptchaVerifier
	proxy    *httputil.ReverseProxy
	tmpl     *template.Template
}

// NewBouncer constructs a Bouncer from configuration.
func NewBouncer(cfg *Config) (*Bouncer, error) {
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}

	sess, err := newSessionManager(cfg.Session)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.ParseFS(templateFS, "templates/captcha.html")
	if err != nil {
		return nil, err
	}

	cache := newDecisionCache()

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Preserve original Host header.
	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
		r.Header.Set("X-Forwarded-For", r.RemoteAddr)
		r.Header.Set("X-Real-IP", clientIP(r, cfg.TrustedProxies))
	}

	return &Bouncer{
		cfg:      cfg,
		cache:    cache,
		session:  sess,
		verifier: newEuCaptchaVerifier(cfg.EuCaptcha),
		proxy:    proxy,
		tmpl:     tmpl,
	}, nil
}

// Cache returns the decision cache so the LAPI client can update it.
func (b *Bouncer) Cache() *decisionCache {
	return b.cache
}

// ServeHTTP is the main handler.
func (b *Bouncer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle the captcha challenge endpoint.
	if r.URL.Path == "/__captcha__" || r.URL.Path == "/__captcha__/" {
		b.serveChallengePage(w, r)
		return
	}
	if r.URL.Path == "/__captcha__/verify" && r.Method == http.MethodPost {
		b.handleVerify(w, r)
		return
	}

	ip := clientIP(r, b.cfg.TrustedProxies)
	decision := b.cache.Lookup(ip)

	switch decision {
	case DecisionBan:
		slog.Info("bouncer: banned", "ip", ip)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return

	case DecisionCaptcha:
		if b.session.IsValid(r, ip) {
			// Already passed the challenge — proxy through.
			b.proxy.ServeHTTP(w, r)
			return
		}
		slog.Info("bouncer: captcha required", "ip", ip)
		// Redirect to challenge page, preserving original URL as redirect target.
		redirect := r.URL.RequestURI()
		http.Redirect(w, r, "/__captcha__?redirect="+url.QueryEscape(redirect), http.StatusFound)
		return

	default:
		// No decision → allow.
		b.proxy.ServeHTTP(w, r)
	}
}

// captchaPageData is passed to the HTML template.
type captchaPageData struct {
	Sitekey  string
	Redirect string
}

func (b *Bouncer) serveChallengePage(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	b.tmpl.ExecuteTemplate(w, "captcha.html", captchaPageData{
		Sitekey:  b.cfg.EuCaptcha.Sitekey,
		Redirect: redirect,
	})
}

func (b *Bouncer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	redirect := r.FormValue("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") {
		redirect = "/"
	}

	ip := clientIP(r, b.cfg.TrustedProxies)
	userAgent := r.UserAgent()

	ok, err := b.verifier.Verify(r.Context(), token, ip, userAgent)
	if err != nil {
		slog.Error("bouncer: captcha verify error", "ip", ip, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !ok {
		slog.Info("bouncer: captcha failed", "ip", ip)
		// Redirect back to challenge page.
		http.Redirect(w, r, "/__captcha__?redirect="+url.QueryEscape(redirect)+"&error=1", http.StatusFound)
		return
	}

	slog.Info("bouncer: captcha passed", "ip", ip)
	b.session.SetCookie(w, ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// clientIP extracts the real client IP, respecting trusted proxy headers.
func clientIP(r *http.Request, trustedCIDRs []string) string {
	if len(trustedCIDRs) > 0 {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if isTrusted(remoteIP, trustedCIDRs) {
			// Trust X-Forwarded-For from this proxy.
			xff := r.Header.Get("X-Forwarded-For")
			if xff != "" {
				// The leftmost IP is the original client.
				parts := strings.Split(xff, ",")
				return strings.TrimSpace(parts[0])
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTrusted(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}
