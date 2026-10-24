// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net"
	"testing"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/ngap/v2"
	"github.com/omec-project/ngap/v2/ngapType"
)

func TestAcceptAmfUeNgapId(t *testing.T) {
	ue := &context.RanUeSharedCtx{AmfUeNgapId: context.AmfUeNgapIdUnspecified}

	if !acceptAmfUeNgapId(ue, 0xFFFFFFFFFF) {
		t.Fatal("an unassigned UE must accept the AMF UE NGAP ID, including the maximum one")
	}
	if ue.AmfUeNgapId != 0xFFFFFFFFFF {
		t.Fatalf("AmfUeNgapId = %d, want it recorded", ue.AmfUeNgapId)
	}
	if !acceptAmfUeNgapId(ue, 0xFFFFFFFFFF) {
		t.Fatal("the same ID must stay consistent")
	}
	if acceptAmfUeNgapId(ue, 1) {
		t.Fatal("a different ID must be rejected once assigned")
	}
	if ue.AmfUeNgapId != 0xFFFFFFFFFF {
		t.Fatal("a rejected ID must not overwrite the assigned one")
	}
}

// newLoopbackAmf returns an AMF whose SCTP connection is wired to the returned server-side
// connection, so the tests can read what the handler sent. The test is skipped when the
// environment offers no SCTP.
func newLoopbackAmf(t *testing.T) (*context.N3IWFAMF, *sctp.SCTPConn) {
	t.Helper()
	// The listener's own Addr() is unreliable with an ephemeral port, so pick a free port first
	tcp, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	tcp.Close()
	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, Port: port}
	ln, err := sctp.ListenSCTP("sctp", laddr)
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan *sctp.SCTPConn, 1)
	go func() {
		conn, acceptErr := ln.AcceptSCTP()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	client, err := sctp.DialSCTP("sctp", nil, laddr)
	if err != nil {
		t.Skipf("SCTP dial failed: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { server.Close() })
	return &context.N3IWFAMF{SCTPConn: client}, server
}

// expectErrorIndication reads one NGAP message from conn and checks it is an Error Indication
// for the given AP IDs with cause Unknown local UE NGAP ID.
func expectErrorIndication(t *testing.T, conn *sctp.SCTPConn, ranUeNgapId, amfUeNgapId int64) {
	t.Helper()
	// SCTPConn has no read deadline, so the read is bounded by a timer instead
	type readResult struct {
		data []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		done <- readResult{buf[:n], err}
	}()
	var res readResult
	select {
	case res = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("no message reached the AMF")
	}
	if res.err != nil {
		t.Fatalf("read: %v", res.err)
	}
	pdu, err := ngap.Decoder(res.data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pdu.InitiatingMessage == nil || pdu.InitiatingMessage.Value.ErrorIndication == nil {
		t.Fatalf("message is not an Error Indication: %+v", pdu)
	}
	var gotRan, gotAmf *int64
	var cause *ngapType.Cause
	for _, ie := range pdu.InitiatingMessage.Value.ErrorIndication.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDRANUENGAPID:
			gotRan = &ie.Value.RANUENGAPID.Value
		case ngapType.ProtocolIEIDAMFUENGAPID:
			gotAmf = &ie.Value.AMFUENGAPID.Value
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause
		}
	}
	if gotRan == nil || *gotRan != ranUeNgapId || gotAmf == nil || *gotAmf != amfUeNgapId {
		t.Fatalf("Error Indication AP IDs = (ran %v, amf %v), want (%d, %d)", gotRan, gotAmf, ranUeNgapId, amfUeNgapId)
	}
	if cause == nil || cause.Present != ngapType.CausePresentRadioNetwork ||
		cause.RadioNetwork.Value != ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID {
		t.Fatalf("Error Indication cause = %+v, want unknown local UE NGAP ID", cause)
	}
}

func rememberHalfOpenUe(amf *context.N3IWFAMF, ranUeNgapId int64) {
	context.N3IWFSelf().RememberReleasedRanUe(&context.N3IWFRanUe{RanUeSharedCtx: context.RanUeSharedCtx{
		RanUeNgapId: ranUeNgapId, AmfUeNgapId: context.AmfUeNgapIdUnspecified, AMF: amf,
	}})
}

// A UE expired while half-open (no AMF UE NGAP ID yet) and the AMF's first reply is an Initial
// Context Setup Request: the AMF must be told about the unknown local UE NGAP ID.
func TestInitialContextSetupRequestForReleasedRanUeSendsErrorIndication(t *testing.T) {
	amf, server := newLoopbackAmf(t)
	const ranUeNgapId, amfUeNgapId = int64(4242), int64(77)
	rememberHalfOpenUe(amf, ranUeNgapId)

	ies := []ngapType.InitialContextSetupRequestIEs{
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:     ngapType.InitialContextSetupRequestIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUeNgapId},
			},
		},
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Value: ngapType.InitialContextSetupRequestIEsValue{
				Present:     ngapType.InitialContextSetupRequestIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUeNgapId},
			},
		},
	}
	pdu := &ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentInitialContextSetup,
				InitialContextSetup: &ngapType.InitialContextSetupRequest{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupRequestIEs{List: ies},
				},
			},
		},
	}

	HandleInitialContextSetupRequest(amf, pdu)
	expectErrorIndication(t, server, ranUeNgapId, amfUeNgapId)

	// The retained state was consumed, so a repeated message is not reported again
	if context.N3IWFSelf().TakeReleasedRanUeAwaitingAmfUeNgapId(amf, ranUeNgapId) != nil {
		t.Fatal("the retained UE must be dropped once reported")
	}
}

// Same delayed first reply, carried by a PDU Session Resource Release Command whose generic
// unknown-UE path would otherwise send an Error Indication without the AMF UE NGAP ID.
func TestPDUSessionResourceReleaseCommandForReleasedRanUeSendsErrorIndication(t *testing.T) {
	amf, server := newLoopbackAmf(t)
	const ranUeNgapId, amfUeNgapId = int64(4243), int64(78)
	rememberHalfOpenUe(amf, ranUeNgapId)

	ies := []ngapType.PDUSessionResourceReleaseCommandIEs{
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
				Present:     ngapType.PDUSessionResourceReleaseCommandIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfUeNgapId},
			},
		},
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
				Present:     ngapType.PDUSessionResourceReleaseCommandIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUeNgapId},
			},
		},
		{
			Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd},
			Value: ngapType.PDUSessionResourceReleaseCommandIEsValue{
				Present:                               ngapType.PDUSessionResourceReleaseCommandIEsPresentPDUSessionResourceToReleaseListRelCmd,
				PDUSessionResourceToReleaseListRelCmd: &ngapType.PDUSessionResourceToReleaseListRelCmd{},
			},
		},
	}
	pdu := &ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentPDUSessionResourceRelease,
				PDUSessionResourceRelease: &ngapType.PDUSessionResourceReleaseCommand{
					ProtocolIEs: ngapType.ProtocolIEContainerPDUSessionResourceReleaseCommandIEs{List: ies},
				},
			},
		},
	}

	HandlePDUSessionResourceReleaseCommand(amf, pdu)
	expectErrorIndication(t, server, ranUeNgapId, amfUeNgapId)
}

// A message from one AMF must not reach a UE served by another AMF: it is an unknown local UE
// NGAP ID for it (TS 38.413 clause 10.6), and it must not adopt that AMF's AMF UE NGAP ID.
func TestLoadRanUeOfAmfRejectsOtherAmf(t *testing.T) {
	amfA, amfB := &context.N3IWFAMF{}, &context.N3IWFAMF{}
	const id = int64(9001)
	ue := &context.N3IWFRanUe{RanUeSharedCtx: context.RanUeSharedCtx{
		RanUeNgapId: id, AmfUeNgapId: context.AmfUeNgapIdUnspecified, AMF: amfA,
	}}
	context.N3IWFSelf().RanUePool.Store(id, ue)
	t.Cleanup(func() { context.N3IWFSelf().RanUePool.Delete(id) })

	if got, ok := loadRanUeOfAmf(amfA, id); !ok || got != context.RanUe(ue) {
		t.Fatal("the serving AMF must find its UE")
	}
	if _, ok := loadRanUeOfAmf(amfB, id); ok {
		t.Fatal("another AMF must not find the UE")
	}
	if _, ok := loadRanUeOfAmf(nil, id); ok {
		t.Fatal("a nil AMF must not match a UE")
	}
	if _, ok := loadRanUeOfAmf(amfA, id+1); ok {
		t.Fatal("an unknown RAN UE NGAP ID must not be found")
	}
	if ue.AmfUeNgapId != context.AmfUeNgapIdUnspecified {
		t.Fatal("a rejected lookup must leave the UE untouched")
	}
}
