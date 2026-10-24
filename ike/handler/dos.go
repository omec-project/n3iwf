// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/ike/message"
)

const (
	// defaultHalfOpenIKESATimeout covers IKE_SA_INIT through the whole 5G NAS registration
	// (primary authentication and security mode with the AMF), which completes only with the
	// final IKE_AUTH, so it must tolerate AMF/AUSF latency and NAS retransmissions.
	defaultHalfOpenIKESATimeout  = 180 * time.Second
	halfOpenIKESACookieThreshold = 256
	halfOpenIKESALimit           = 1024
	// halfOpenIKESAPerSourceLimit bounds the pending IKE SAs one source address may hold. The
	// cookie only proves that the source can receive replies, so a reachable host could otherwise
	// fill the global limit and keep every other UE out.
	halfOpenIKESAPerSourceLimit = 32
	// preAuthIKESATimeout bounds an IKE SA that has not started IKE_AUTH. A UE sends IKE_AUTH
	// right after the IKE_SA_INIT response, so the long half-open timeout, which covers the whole
	// NAS registration, is not needed until then.
	preAuthIKESATimeout = 30 * time.Second
	// cookieSecretLifetime is how long one COOKIE secret is used for new cookies. A cookie is
	// accepted for the current and the previous secret, so it lives between one and two lifetimes,
	// which is far more than the IKE_SA_INIT retry it is meant for.
	cookieSecretLifetime = 60 * time.Second
	// HalfOpenIKESASweepInterval is how often expired half-open IKE SAs are reclaimed when no
	// IKE_SA_INIT request is arriving to trigger the check
	HalfOpenIKESASweepInterval = 10 * time.Second
)

// ExpireHalfOpenIKESAs reclaims IKE SAs that did not complete authentication within
// the half-open timeout, together with any RAN UE already allocated for them. It must be called
// from the IKE event loop.
func ExpireHalfOpenIKESAs() {
	halfOpenIKESAStats("")
}

// halfOpenIKESAStats expires timed-out pending IKE SAs and returns the number of pending IKE
// SAs, in total and for remoteIP
func halfOpenIKESAStats(remoteIP string) (total, fromRemote int) {
	maxAge := halfOpenIKESATimeout()
	return context.N3IWFSelf().HalfOpenIKESACount(maxAge, min(maxAge, preAuthIKESATimeout), remoteIP)
}

// halfOpenIKESATimeout returns the configured half-open timeout, or the default if unset
func halfOpenIKESATimeout() time.Duration {
	if t := context.N3IWFSelf().HalfOpenIKESATimeout; t > 0 {
		return t
	}
	return defaultHalfOpenIKESATimeout
}

// cookieKeys holds the secrets that key the stateless COOKIE computation. They are random per
// process and rotated every cookieSecretLifetime (RFC 7296 section 2.6 recommends changing the
// secret periodically), so a captured cookie cannot be replayed to create IKE SAs for long.
type cookieKeys struct {
	mu        sync.Mutex
	current   []byte
	previous  []byte
	rotatedAt time.Time
}

var cookies cookieKeys

func newCookieSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("cannot initialise IKE cookie secret: " + err.Error())
	}
	return secret
}

// secrets returns the current and the previous secret at now, rotating first when due
func (k *cookieKeys) secrets(now time.Time) (current, previous []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch elapsed := now.Sub(k.rotatedAt); {
	case k.current == nil || elapsed < 0 || elapsed >= 2*cookieSecretLifetime:
		// First use, clock stepped back or idle for so long that even the previous secret is
		// stale: no earlier cookie may stay valid
		k.current, k.previous, k.rotatedAt = newCookieSecret(), newCookieSecret(), now
	case elapsed >= cookieSecretLifetime:
		k.current, k.previous, k.rotatedAt = newCookieSecret(), k.current, now
	}
	return k.current, k.previous
}

// computeCookie returns HMAC(secret, Ni | IPi | SPIi), a keyed variant of the example in
// RFC 7296 section 2.6 (Hash(Ni | IPi | SPIi | <secret>)). The section leaves the algorithm open.
func computeCookie(secret, nonce []byte, ueAddr *net.UDPAddr, initiatorSPI uint64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(nonce)
	mac.Write(ueAddr.IP)
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], initiatorSPI)
	mac.Write(spi[:])
	return mac.Sum(nil)
}

// newCookie returns the cookie to send for a request with this nonce, source and initiator SPI
func newCookie(nonce []byte, ueAddr *net.UDPAddr, initiatorSPI uint64) []byte {
	current, _ := cookies.secrets(time.Now())
	return computeCookie(current, nonce, ueAddr, initiatorSPI)
}

// hasValidCookie reports whether the request carries a COOKIE notification matching the cookie
// that would be issued for the same nonce, source address and initiator SPI. RFC 7296 section
// 2.6 requires the retried request to carry it as the first payload after the header.
func hasValidCookie(payloads []message.IKEPayload, nonce []byte, ueAddr *net.UDPAddr, initiatorSPI uint64) bool {
	if len(payloads) == 0 {
		return false
	}
	n, ok := payloads[0].(*message.Notification)
	if !ok || n.NotifyMessageType != message.COOKIE {
		return false
	}
	current, previous := cookies.secrets(time.Now())
	// Both comparisons are always made so the time taken does not tell which secret matched
	okCurrent := hmac.Equal(n.NotificationData, computeCookie(current, nonce, ueAddr, initiatorSPI))
	okPrevious := hmac.Equal(n.NotificationData, computeCookie(previous, nonce, ueAddr, initiatorSPI))
	return okCurrent || okPrevious
}
