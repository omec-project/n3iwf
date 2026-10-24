// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"testing"
)

func TestResolveUDPAddrContext(t *testing.T) {
	addr, err := ResolveUDPAddrContext(context.Background(), "127.0.0.1:2152")
	if err != nil {
		t.Fatalf("IP literal: %v", err)
	}
	if addr.IP.String() != "127.0.0.1" || addr.Port != 2152 {
		t.Errorf("unexpected address %v", addr)
	}

	addr, err = ResolveUDPAddrContext(context.Background(), ":500")
	if err != nil || addr.IP != nil || addr.Port != 500 {
		t.Errorf("empty host: %v, %v", addr, err)
	}

	if _, err = ResolveUDPAddrContext(context.Background(), "no-port"); err == nil {
		t.Error("an address without a port must be rejected")
	}
}

func TestResolveUDPAddrContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveUDPAddrContext(ctx, "upf.invalid:2152"); err == nil {
		t.Error("resolving a host name must fail once the context is cancelled")
	}
}

func TestResolveIPAddrContext(t *testing.T) {
	addr, err := ResolveIPAddrContext(context.Background(), "ip", "127.0.0.1")
	if err != nil || addr.IP.String() != "127.0.0.1" {
		t.Fatalf("IPv4 literal: %v, %v", addr, err)
	}
	addr, err = ResolveIPAddrContext(context.Background(), "ip", "::1")
	if err != nil || addr.IP.String() != "::1" {
		t.Fatalf("IPv6 literal: %v, %v", addr, err)
	}
	if _, err = ResolveIPAddrContext(context.Background(), "ip4", "::1"); err == nil {
		t.Error("an IPv6 literal must be rejected for network ip4")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = ResolveIPAddrContext(ctx, "ip", "amf.invalid"); err == nil {
		t.Error("resolving a host name must fail once the context is cancelled")
	}
}
