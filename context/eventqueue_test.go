// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"
	"time"
)

func TestAsyncSenderDoesNotBlockAndKeepsOrder(t *testing.T) {
	ch := make(chan int, 1) // far smaller than the number of events queued below
	var s asyncSender[int]

	const n = 100
	done := make(chan struct{})
	go func() {
		for i := range n {
			s.send(ch, i)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("send blocked on a full channel")
	}

	for want := range n {
		select {
		case got := <-ch:
			if got != want {
				t.Fatalf("event out of order: got %d, want %d", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("event %d was not delivered", want)
		}
	}
}

func TestReleasedRanUeLookups(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	amfA, amfB := &N3IWFAMF{}, &N3IWFAMF{}

	// Released before the AMF UE NGAP ID was known: the ID pair supplies it
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{
		RanUeNgapId: 1, AmfUeNgapId: AmfUeNgapIdUnspecified, AMF: amfA,
	}})
	if n3iwfCtx.TakeReleasedRanUeByIdPair(amfB, 1, 10) != nil {
		t.Error("another AMF must not consume the entry")
	}
	got := n3iwfCtx.TakeReleasedRanUeByIdPair(amfA, 1, 10)
	if got == nil || got.AmfUeNgapId != 10 {
		t.Fatalf("ID pair lookup failed or did not populate the AMF UE NGAP ID: %+v", got)
	}
	if n3iwfCtx.TakeReleasedRanUeByIdPair(amfA, 1, 10) != nil {
		t.Error("an entry must be returned only once")
	}

	// The same AMF UE NGAP ID used by two AMFs
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 2, AmfUeNgapId: 20, AMF: amfA}})
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 3, AmfUeNgapId: 20, AMF: amfB}})
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfB, 20); got == nil || got.RanUeNgapId != 3 {
		t.Fatalf("lookup must return the requesting AMF's UE: %+v", got)
	}
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 20); got == nil || got.RanUeNgapId != 2 {
		t.Fatalf("the other AMF's entry must have been left alone: %+v", got)
	}

	// A pair that contradicts the stored AMF UE NGAP ID does not match
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 4, AmfUeNgapId: 40, AMF: amfA}})
	if n3iwfCtx.TakeReleasedRanUeByIdPair(amfA, 4, 41) != nil {
		t.Error("a pair with a different AMF UE NGAP ID must not match")
	}
}

func TestReleasedRanUeIsBounded(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	for i := range int64(maxReleasedRanUe + 10) {
		n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 100 + i, AmfUeNgapId: 1000 + i}})
	}
	if got := len(n3iwfCtx.releasedRanUe); got > maxReleasedRanUe {
		t.Errorf("retained %d entries, limit is %d", got, maxReleasedRanUe)
	}
}
