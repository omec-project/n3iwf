// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/n3iwf/ike/message"
)

func cookiePayloads(cookie []byte) []message.IKEPayload {
	return []message.IKEPayload{&message.Notification{NotifyMessageType: message.COOKIE, NotificationData: cookie}}
}

func TestCookieAcceptedForSameRequestOnly(t *testing.T) {
	ue := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 500}
	nonce := []byte("0123456789abcdef")
	cookie := newCookie(nonce, ue, 7)

	if !hasValidCookie(cookiePayloads(cookie), nonce, ue, 7) {
		t.Fatal("the cookie issued for a request must be accepted on its retry")
	}
	if hasValidCookie(cookiePayloads(cookie), nonce, ue, 8) {
		t.Error("a cookie must be bound to the initiator SPI")
	}
	if hasValidCookie(cookiePayloads(cookie), nonce, &net.UDPAddr{IP: net.ParseIP("192.0.2.2")}, 7) {
		t.Error("a cookie must be bound to the source address")
	}
	if hasValidCookie(cookiePayloads(cookie), []byte("another nonce..."), ue, 7) {
		t.Error("a cookie must be bound to the initiator nonce")
	}
}

func TestCookieMustBeFirstPayload(t *testing.T) {
	ue := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 500}
	nonce := []byte("0123456789abcdef")
	cookie := newCookie(nonce, ue, 7)

	other := &message.Notification{NotifyMessageType: message.NAT_DETECTION_SOURCE_IP}
	later := append([]message.IKEPayload{other}, cookiePayloads(cookie)...)
	if hasValidCookie(later, nonce, ue, 7) {
		t.Error("RFC 7296 section 2.6: the COOKIE must be the first payload")
	}
	if hasValidCookie(nil, nonce, ue, 7) {
		t.Error("a request without payloads has no cookie")
	}
}

func TestCookieSecretRotation(t *testing.T) {
	var k cookieKeys
	t0 := time.Now()
	first, _ := k.secrets(t0)
	if again, _ := k.secrets(t0.Add(cookieSecretLifetime - time.Second)); string(again) != string(first) {
		t.Fatal("the secret must not change within its lifetime")
	}

	second, prev := k.secrets(t0.Add(cookieSecretLifetime))
	if string(second) == string(first) {
		t.Fatal("the secret must rotate after its lifetime")
	}
	if string(prev) != string(first) {
		t.Fatal("a cookie of the previous secret must still be accepted for one more lifetime")
	}

	// Idle for longer than two lifetimes: no earlier cookie may remain valid
	third, prev := k.secrets(t0.Add(4 * cookieSecretLifetime))
	if string(third) == string(second) || string(prev) == string(second) || string(prev) == string(first) {
		t.Fatal("secrets older than two lifetimes must be discarded")
	}
}
