// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"io"
	"sync"
)

// socketRegistry tracks the sockets a service has opened so that shutdown can close them. A
// receiver registers its socket before it reports a successful start, and shutdown may run at
// any time, including while a later service is still starting, hence the lock. Once shutdown
// has taken the sockets the registry refuses new ones, so a receiver that was still dialing
// closes its socket itself instead of leaking it.
//
// The zero value is ready to use.
type socketRegistry[T io.Closer] struct {
	mu      sync.Mutex
	items   []T
	stopped bool
}

// add registers item. It returns false, without registering, once shutdown has begun.
func (r *socketRegistry[T]) add(item T) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.items = append(r.items, item)
	return true
}

// shutdown refuses further registrations and returns the sockets registered so far
func (r *socketRegistry[T]) shutdown() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	items := r.items
	r.items = nil
	return items
}
