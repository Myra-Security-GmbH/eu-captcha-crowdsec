/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sessionManager issues and validates HMAC-signed session cookies.
// Cookie format: base64(ip + ":" + unix_expiry) + "." + base64(hmac)
type sessionManager struct {
	secret     []byte
	cookieName string
	ttl        time.Duration
}

func newSessionManager(cfg SessionConfig) (*sessionManager, error) {
	ttl, err := time.ParseDuration(cfg.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid session.ttl %q: %w", cfg.TTL, err)
	}
	return &sessionManager{
		secret:     []byte(cfg.Secret),
		cookieName: cfg.CookieName,
		ttl:        ttl,
	}, nil
}

// IsValid checks whether the request carries a valid session cookie for the
// given client IP.
func (s *sessionManager) IsValid(r *http.Request, ip string) bool {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return false
	}
	return s.verify(c.Value, ip)
}

// SetCookie writes a new signed session cookie to the response.
func (s *sessionManager) SetCookie(w http.ResponseWriter, ip string) {
	expiry := time.Now().Add(s.ttl).Unix()
	payload := ip + ":" + strconv.FormatInt(expiry, 10)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := s.sign(encoded)
	value := encoded + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Unix(expiry, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *sessionManager) verify(value, ip string) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	encoded, sig := parts[0], parts[1]

	// Verify HMAC.
	if s.sign(encoded) != sig {
		return false
	}

	// Decode payload.
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	payload := strings.SplitN(string(raw), ":", 2)
	if len(payload) != 2 {
		return false
	}
	cookieIP, expiryStr := payload[0], payload[1]

	// Verify IP matches.
	if cookieIP != ip {
		return false
	}

	// Verify not expired.
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}

	return true
}

func (s *sessionManager) sign(data string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
