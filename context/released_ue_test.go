// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
	"testing"
	"time"
)

func TestReleasedRanUeAmfOnlyLookupSkipsUnknownId(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	amf := &N3IWFAMF{}
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{
		RanUeNgapId: 1, AmfUeNgapId: AmfUeNgapIdUnspecified, AMF: amf,
	}})
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amf, AmfUeNgapIdUnspecified); got != nil {
		t.Fatalf("an entry without an AMF UE NGAP ID must not match the sentinel value: %+v", got)
	}
	if got := n3iwfCtx.TakeReleasedRanUeByIdPair(amf, 1, 10); got == nil {
		t.Fatal("the entry must still be reachable through the ID pair")
	}
}

func TestTakeReleasedRanUeAwaitingAmfUeNgapId(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	amfA, amfB := &N3IWFAMF{}, &N3IWFAMF{}
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{
		RanUeNgapId: 1, AmfUeNgapId: AmfUeNgapIdUnspecified, AMF: amfA,
	}})
	// A Release Request was already sent for this one, so its Release Command is still expected
	n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{
		RanUeNgapId: 3, AmfUeNgapId: 30, AMF: amfA,
	}})

	if n3iwfCtx.TakeReleasedRanUeAwaitingAmfUeNgapId(amfB, 1) != nil {
		t.Error("another AMF must not match")
	}
	if n3iwfCtx.TakeReleasedRanUeAwaitingAmfUeNgapId(amfA, 2) != nil {
		t.Error("another RAN UE NGAP ID must not match")
	}
	if n3iwfCtx.TakeReleasedRanUeAwaitingAmfUeNgapId(amfA, 3) != nil {
		t.Error("an entry that already has an AMF UE NGAP ID must be left for its Release Command")
	}
	if n3iwfCtx.TakeReleasedRanUeAwaitingAmfUeNgapId(amfA, 1) == nil {
		t.Fatal("the entry awaiting an AMF UE NGAP ID was not returned")
	}
	if n3iwfCtx.TakeReleasedRanUeAwaitingAmfUeNgapId(amfA, 1) != nil {
		t.Error("an entry must be returned only once, so the Error Indication is sent only once")
	}
	if got := n3iwfCtx.TakeReleasedRanUeByIdPair(amfA, 1, 10); got != nil {
		t.Errorf("the entry must be forgotten once reported: %+v", got)
	}
	if n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 30) == nil {
		t.Error("the entry that already had an ID must stay retained")
	}
}

func TestFindUeByAmfUeNgapIDIgnoresUnassigned(t *testing.T) {
	amf := &N3IWFAMF{}
	amf.init("", nil)
	ue := &N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 1, AmfUeNgapId: AmfUeNgapIdUnspecified}}
	amf.AttachRanUe(ue)
	if got := amf.FindUeByAmfUeNgapID(AmfUeNgapIdUnspecified); got != nil {
		t.Errorf("a UE without an AMF UE NGAP ID must not be found by the sentinel: %+v", got)
	}
}

func TestSocketRegistryRefusesAfterShutdown(t *testing.T) {
	var r socketRegistry[*net.UDPConn]
	c1 := &net.UDPConn{}
	if !r.add(c1) {
		t.Fatal("add before shutdown must succeed")
	}
	if got := r.shutdown(); len(got) != 1 || got[0] != c1 {
		t.Fatalf("shutdown must return the registered sockets, got %v", got)
	}
	if r.add(&net.UDPConn{}) {
		t.Error("add after shutdown must be refused so the caller closes the socket itself")
	}
	if got := r.shutdown(); len(got) != 0 {
		t.Errorf("sockets must be handed out only once, got %v", got)
	}
}

// maxAmfUeNgapId is the largest value of the AMF UE NGAP ID IE, INTEGER (0..1099511627775)
const maxAmfUeNgapId int64 = 1<<40 - 1

func TestMaximumAmfUeNgapIdIsAssignable(t *testing.T) {
	if AmfUeNgapIdUnspecified >= 0 || AmfUeNgapIdUnspecified == maxAmfUeNgapId {
		t.Fatalf("the sentinel %d must lie outside the IE range", AmfUeNgapIdUnspecified)
	}

	amf := &N3IWFAMF{}
	amf.init("", nil)
	ue := &N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{RanUeNgapId: 1, AmfUeNgapId: maxAmfUeNgapId}}
	amf.AttachRanUe(ue)
	if got := amf.FindUeByAmfUeNgapID(maxAmfUeNgapId); got != RanUe(ue) {
		t.Errorf("a UE holding the maximum AMF UE NGAP ID must be found, got %v", got)
	}

	n3iwfCtx := &N3IWFContext{}
	n3iwfCtx.RememberReleasedRanUe(ue)
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amf, maxAmfUeNgapId); got != nil {
		t.Errorf("entry belongs to a different AMF, must not match: %+v", got)
	}
	ue.AMF = amf
	n3iwfCtx.RememberReleasedRanUe(ue)
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amf, maxAmfUeNgapId); got == nil {
		t.Error("a retained UE holding the maximum AMF UE NGAP ID must be found")
	}
}

func TestPurgeReleasedRanUeOnNgReset(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	amfA, amfB := &N3IWFAMF{}, &N3IWFAMF{}
	remember := func(amf *N3IWFAMF, ranId, amfId int64) {
		n3iwfCtx.RememberReleasedRanUe(&N3IWFRanUe{RanUeSharedCtx: RanUeSharedCtx{
			RanUeNgapId: ranId, AmfUeNgapId: amfId, AMF: amf,
		}})
	}

	// Full reset drops only the entries of the resetting AMF
	remember(amfA, 1, 10)
	remember(amfB, 2, 20)
	n3iwfCtx.PurgeReleasedRanUesOfAmf(amfA)
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 10); got != nil {
		t.Errorf("entry must be purged by a full reset: %+v", got)
	}
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfB, 20); got == nil {
		t.Error("entry of another AMF must survive")
	}

	// Identifier reuse after a reset must not resolve to the pre-reset entry
	remember(amfA, 3, 30)
	n3iwfCtx.PurgeReleasedRanUesOfAmf(amfA)
	remember(amfA, 4, 30)
	if got := n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 30); got == nil || got.RanUeNgapId != 4 {
		t.Errorf("reused AMF UE NGAP ID must resolve to the new entry, got %+v", got)
	}

	// Partial reset by RAN UE NGAP ID, by AMF UE NGAP ID, and by a mismatching pair
	remember(amfA, 5, 50)
	remember(amfA, 6, 60)
	remember(amfA, 7, 70)
	ran5, amf6, ran7, wrong := int64(5), int64(60), int64(7), int64(71)
	n3iwfCtx.PurgeReleasedRanUe(amfA, &ran5, nil)
	n3iwfCtx.PurgeReleasedRanUe(amfA, nil, &amf6)
	n3iwfCtx.PurgeReleasedRanUe(amfA, &ran7, &wrong)
	n3iwfCtx.PurgeReleasedRanUe(amfB, &ran7, nil)
	if n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 50) != nil || n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 60) != nil {
		t.Error("entries named by a partial reset must be purged")
	}
	if n3iwfCtx.TakeReleasedRanUeByAmfUeNgapId(amfA, 70) == nil {
		t.Error("entry with a conflicting pair or another AMF must survive")
	}
}

func TestHalfOpenIKESACountPerSourceAndPreAuthTimeout(t *testing.T) {
	n3iwfCtx := &N3IWFContext{}
	now := time.Now()
	add := func(spi uint64, ip string, age time.Duration, state uint8) {
		sa := &IKESecurityAssociation{CreatedAt: now.Add(-age), RemoteIP: ip, State: state, LocalSPI: spi}
		n3iwfCtx.IkeSA.Store(spi, sa)
		n3iwfCtx.PendingIkeSA.Store(spi, sa)
	}
	add(1, "10.0.0.1", time.Second, 0)
	add(2, "10.0.0.1", time.Second, 1)
	add(3, "10.0.0.2", time.Second, 0)
	add(4, "10.0.0.1", time.Minute, 0) // never started IKE_AUTH: pre-AUTH timeout
	add(5, "10.0.0.1", time.Minute, 1) // in registration: still within the long timeout
	add(6, "10.0.0.1", 10*time.Minute, 1)

	total, fromSource := n3iwfCtx.HalfOpenIKESACount(5*time.Minute, 30*time.Second, "10.0.0.1")
	if total != 4 || fromSource != 3 {
		t.Fatalf("total, fromSource = %d, %d; want 4, 3", total, fromSource)
	}
	for _, spi := range []uint64{4, 6} {
		if n3iwfCtx.IsIKESAPending(spi) {
			t.Errorf("SPI %d must have been expired", spi)
		}
		if _, ok := n3iwfCtx.IKESALoad(spi); ok {
			t.Errorf("SPI %d must have been removed", spi)
		}
	}
	if _, fromNone := n3iwfCtx.HalfOpenIKESACount(5*time.Minute, 30*time.Second, ""); fromNone != 0 {
		t.Errorf("an empty address must match no SA, got %d", fromNone)
	}
}
