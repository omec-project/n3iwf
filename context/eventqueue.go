// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import "sync"

// asyncSender delivers events to a channel from a goroutine of its own, so the caller never
// blocks on a full channel, no event is dropped, and events keep the order in which they were
// queued. It exists for producers that run inside one event loop and feed another, where two
// loops blocking on each other's full channels would deadlock both.
//
// The zero value is ready to use. The consumer channel must stay open and must keep being
// drained (see the event loops' shutdown handling), otherwise the delivery goroutine
// blocks.
type asyncSender[T any] struct {
	mu       sync.Mutex
	pending  []T
	draining bool
}

// send queues evt for delivery to ch and returns immediately
func (s *asyncSender[T]) send(ch chan<- T, evt T) {
	s.mu.Lock()
	s.pending = append(s.pending, evt)
	if s.draining {
		s.mu.Unlock()
		return
	}
	s.draining = true
	s.mu.Unlock()

	go s.drain(ch)
}

// drain delivers queued events until none remain
func (s *asyncSender[T]) drain(ch chan<- T) {
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.pending = nil
			s.draining = false
			s.mu.Unlock()
			return
		}
		evt := s.pending[0]
		var zero T
		s.pending[0] = zero
		s.pending = s.pending[1:]
		s.mu.Unlock()

		ch <- evt
	}
}
