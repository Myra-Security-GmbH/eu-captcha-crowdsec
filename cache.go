/*
 * Copyright (c) Myra Security GmbH 2026.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package crowdsec

import (
	"net"
	"sync"
)

// DecisionType represents the action CrowdSec has decided for an IP.
type DecisionType int

const (
	DecisionAllow   DecisionType = iota // no decision → allow
	DecisionBan                         // ban → 403
	DecisionCaptcha                     // captcha → challenge
)

// decisionCache stores active CrowdSec decisions indexed by IP network.
// Reads are far more frequent than writes, so a read-write mutex is used.
type decisionCache struct {
	mu    sync.RWMutex
	nets  map[string]*net.IPNet // CIDR → decision
	ips   map[string]DecisionType // single IP → decision (optimised fast path)
}

func newDecisionCache() *decisionCache {
	return &decisionCache{
		nets: make(map[string]*net.IPNet),
		ips:  make(map[string]DecisionType),
	}
}

// Lookup returns the decision for the given IP string.
// Returns DecisionAllow when no decision is present.
func (c *decisionCache) Lookup(ipStr string) DecisionType {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if dt, ok := c.ips[ipStr]; ok {
		return dt
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return DecisionAllow
	}
	for _, network := range c.nets {
		if network.Contains(ip) {
			return c.ips[network.String()]
		}
	}
	return DecisionAllow
}

// Apply applies a batch of delta decisions.
// new decisions are added; deleted decisions are removed.
func (c *decisionCache) Apply(added []Decision, deleted []Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, d := range deleted {
		key, _ := normalizeScope(d.Value)
		delete(c.ips, key)
		delete(c.nets, key)
	}

	for _, d := range added {
		dt := decisionTypeFromString(d.Type)
		key, network := normalizeScope(d.Value)
		c.ips[key] = dt
		if network != nil {
			c.nets[key] = network
		}
	}
}

// Reset replaces all decisions at once (used on first boot / startup sync).
func (c *decisionCache) Reset(decisions []Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nets = make(map[string]*net.IPNet, len(decisions))
	c.ips = make(map[string]DecisionType, len(decisions))

	for _, d := range decisions {
		dt := decisionTypeFromString(d.Type)
		key, network := normalizeScope(d.Value)
		c.ips[key] = dt
		if network != nil {
			c.nets[key] = network
		}
	}
}

func normalizeScope(value string) (string, *net.IPNet) {
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network.String(), network
	}
	// Plain IP.
	return value, nil
}

func decisionTypeFromString(s string) DecisionType {
	switch s {
	case "ban":
		return DecisionBan
	case "captcha":
		return DecisionCaptcha
	default:
		return DecisionAllow
	}
}
