// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"sync/atomic"
	"time"
)

// Timer wraps a periodic ticker and cancellation context
// for safe and efficient resource management.
type Timer struct {
	cancel context.CancelFunc
}

// NewDPDPeriodicTimer starts a periodic timer that increments retry count
// and cancels when maxRetryTimes is reached.
func NewDPDPeriodicTimer(
	d time.Duration,
	maxRetryTimes int32,
	ikeSA *IKESecurityAssociation,
	cancelFunc func(),
) *Timer {
	ctx, cancel := context.WithCancel(context.Background())
	t := &Timer{cancel: cancel}

	go func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if atomic.AddInt32(&ikeSA.CurrentRetryTimes, 1) > maxRetryTimes {
					cancelFunc()
					return
				}
			}
		}
	}()

	return t
}

// Stop cancels the timer and cleans up resources.
func (t *Timer) Stop() {
	if t.cancel != nil {
		t.cancel()
	}
}
