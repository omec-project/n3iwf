// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"
	"time"

	"github.com/omec-project/n3iwf/context"
)

// After the NGAP loop has ended, discardEvents must keep draining the channel, including
// the expiry events it still handles locally, and must return once the channel is closed.
func TestDiscardEventsKeepsDraining(t *testing.T) {
	ch := make(chan context.NgapEvt, 2)
	done := make(chan struct{})
	go func() {
		discardEvents(ch)
		close(done)
	}()

	// No such RAN UE: handled (a no-op) without panicking
	ch <- context.NewExpireHalfOpenRanUeEvt(424242)
	ch <- context.NewSendNASMsgEvt(1)
	close(ch)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("discardEvents did not drain and return")
	}
}
