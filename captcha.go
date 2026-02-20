/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// euCaptchaVerifier verifies EU CAPTCHA tokens server-side.
type euCaptchaVerifier struct {
	sitekey    string
	secret     string
	verifyURL  string
	httpClient *http.Client
}

func newEuCaptchaVerifier(cfg EuCaptchaConfig) *euCaptchaVerifier {
	return &euCaptchaVerifier{
		sitekey:    cfg.Sitekey,
		secret:     cfg.Secret,
		verifyURL:  cfg.VerifyURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type verifyRequest struct {
	Sitekey         string `json:"sitekey"`
	Secret          string `json:"secret"`
	ClientIP        string `json:"client_ip"`
	ClientToken     string `json:"client_token"`
	ClientUserAgent string `json:"client_user_agent"`
}

type verifyResponse struct {
	Success bool `json:"success"`
	Train   bool `json:"train"`
}

// Verify calls the EU CAPTCHA API. Returns true only when success is true and
// train is false (trained responses are shadow-passes that should not grant access).
func (v *euCaptchaVerifier) Verify(ctx context.Context, token, clientIP, userAgent string) (bool, error) {
	body, err := json.Marshal(verifyRequest{
		Sitekey:         v.sitekey,
		Secret:          v.secret,
		ClientIP:        clientIP,
		ClientToken:     token,
		ClientUserAgent: userAgent,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("eu-captcha verify request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("eu-captcha verify: unexpected status %d", resp.StatusCode)
	}

	var vr verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return false, fmt.Errorf("eu-captcha verify: decode response: %w", err)
	}

	// train:true means the request was used as a training sample and should be
	// treated as a failure — do not grant access.
	return vr.Success && !vr.Train, nil
}
