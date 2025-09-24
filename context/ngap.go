// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"github.com/ishidawataru/sctp"
	"github.com/omec-project/ngap/ngapType"
)

// NgapServer manages SCTP connections and event channels
type NgapServer struct {
	Conn         []*sctp.SCTPConn
	RcvNgapPktCh chan NgapReceivePacket
	RcvEventCh   chan NgapEvt
}

// NgapReceivePacket represents a received NGAP packet
type NgapReceivePacket struct {
	Conn *sctp.SCTPConn
	Buf  []byte
}

// NgapEventType enumerates NGAP event types
type NgapEventType int64

const (
	UnmarshalEAP5GData NgapEventType = iota
	NASTCPConnEstablishedComplete
	GetNGAPContext
	SendInitialUEMessage
	SendPDUSessionResourceSetupResponse
	SendNASMsg
	StartTCPSignalNASMsg
	SendUEContextRelease
	SendUEContextReleaseRequest
	SendUEContextReleaseComplete
	SendPDUSessionResourceRelease
	SendPDUSessionResourceReleaseResponse
	SendUplinkNASTransport
	SendInitialContextSetupResponse
)

// EvtError represents NGAP event errors
type EvtError string

func (e EvtError) Error() string { return string(e) }

const (
	ErrNil                          = EvtError("Nil")
	ErrRadioConnWithUeLost          = EvtError("RadioConnectionWithUeLost")
	ErrTransportResourceUnavailable = EvtError("TransportResourceUnavailable")
	ErrAMFSelection                 = EvtError("No available AMF for this UE")
)

// NgapEvt is the interface for all NGAP events
type NgapEvt interface {
	Type() NgapEventType
}

// UnmarshalEAP5GDataEvt event
type UnmarshalEAP5GDataEvt struct {
	LocalSPI      uint64
	EAPVendorData []byte
	IsInitialUE   bool
	RanUeNgapId   int64
}

func (e *UnmarshalEAP5GDataEvt) Type() NgapEventType { return UnmarshalEAP5GData }

func NewUnmarshalEAP5GDataEvt(localSPI uint64, eapVendorData []byte, isInitialUE bool, ranUeNgapId int64) *UnmarshalEAP5GDataEvt {
	return &UnmarshalEAP5GDataEvt{LocalSPI: localSPI, EAPVendorData: eapVendorData, IsInitialUE: isInitialUE, RanUeNgapId: ranUeNgapId}
}

// SendInitialUEMessageEvt event
type SendInitialUEMessageEvt struct {
	RanUeNgapId int64
	IPv4Addr    string
	IPv4Port    int
	NasPDU      []byte
}

func (e *SendInitialUEMessageEvt) Type() NgapEventType { return SendInitialUEMessage }

func NewSendInitialUEMessageEvt(ranUeNgapId int64, ipv4Addr string, ipv4Port int, nasPDU []byte) *SendInitialUEMessageEvt {
	return &SendInitialUEMessageEvt{RanUeNgapId: ranUeNgapId, IPv4Addr: ipv4Addr, IPv4Port: ipv4Port, NasPDU: nasPDU}
}

// SendPDUSessionResourceSetupResEvt event
type SendPDUSessionResourceSetupResEvt struct {
	RanUeNgapId int64
}

func (e *SendPDUSessionResourceSetupResEvt) Type() NgapEventType {
	return SendPDUSessionResourceSetupResponse
}

func NewSendPDUSessionResourceSetupResEvt(ranUeNgapId int64) *SendPDUSessionResourceSetupResEvt {
	return &SendPDUSessionResourceSetupResEvt{RanUeNgapId: ranUeNgapId}
}

// SendNASMsgEvt event
type SendNASMsgEvt struct {
	RanUeNgapId int64
}

func (e *SendNASMsgEvt) Type() NgapEventType { return SendNASMsg }

func NewSendNASMsgEvt(ranUeNgapId int64) *SendNASMsgEvt {
	return &SendNASMsgEvt{RanUeNgapId: ranUeNgapId}
}

// StartTCPSignalNASMsgEvt event
type StartTCPSignalNASMsgEvt struct {
	RanUeNgapId int64
}

func (e *StartTCPSignalNASMsgEvt) Type() NgapEventType { return StartTCPSignalNASMsg }

func NewStartTCPSignalNASMsgEvt(ranUeNgapId int64) *StartTCPSignalNASMsgEvt {
	return &StartTCPSignalNASMsgEvt{RanUeNgapId: ranUeNgapId}
}

// NASTCPConnEstablishedCompleteEvt event
type NASTCPConnEstablishedCompleteEvt struct {
	RanUeNgapId int64
}

func (e *NASTCPConnEstablishedCompleteEvt) Type() NgapEventType { return NASTCPConnEstablishedComplete }

func NewNASTCPConnEstablishedCompleteEvt(ranUeNgapId int64) *NASTCPConnEstablishedCompleteEvt {
	return &NASTCPConnEstablishedCompleteEvt{RanUeNgapId: ranUeNgapId}
}

// SendUEContextReleaseRequestEvt event
type SendUEContextReleaseRequestEvt struct {
	RanUeNgapId int64
	ErrMsg      EvtError
}

func (e *SendUEContextReleaseRequestEvt) Type() NgapEventType { return SendUEContextReleaseRequest }

func NewSendUEContextReleaseRequestEvt(ranUeNgapId int64, errMsg EvtError) *SendUEContextReleaseRequestEvt {
	return &SendUEContextReleaseRequestEvt{RanUeNgapId: ranUeNgapId, ErrMsg: errMsg}
}

// SendUEContextReleaseCompleteEvt event
type SendUEContextReleaseCompleteEvt struct {
	RanUeNgapId int64
}

func (e *SendUEContextReleaseCompleteEvt) Type() NgapEventType { return SendUEContextReleaseComplete }

func NewSendUEContextReleaseCompleteEvt(ranUeNgapId int64) *SendUEContextReleaseCompleteEvt {
	return &SendUEContextReleaseCompleteEvt{RanUeNgapId: ranUeNgapId}
}

// SendPDUSessionResourceReleaseResEvt event
type SendPDUSessionResourceReleaseResEvt struct {
	RanUeNgapId int64
}

func (e *SendPDUSessionResourceReleaseResEvt) Type() NgapEventType {
	return SendPDUSessionResourceReleaseResponse
}

func NewSendPDUSessionResourceReleaseResEvt(ranUeNgapId int64) *SendPDUSessionResourceReleaseResEvt {
	return &SendPDUSessionResourceReleaseResEvt{RanUeNgapId: ranUeNgapId}
}

// Ngap context constant
const CxtTempPDUSessionSetupData int64 = iota

// GetNGAPContextEvt event
type GetNGAPContextEvt struct {
	RanUeNgapId       int64
	NgapCxtReqNumlist []int64
}

func (e *GetNGAPContextEvt) Type() NgapEventType { return GetNGAPContext }

func NewGetNGAPContextEvt(ranUeNgapId int64, ngapCxtReqNumlist []int64) *GetNGAPContextEvt {
	return &GetNGAPContextEvt{RanUeNgapId: ranUeNgapId, NgapCxtReqNumlist: ngapCxtReqNumlist}
}

// SendUplinkNASTransportEvt event
type SendUplinkNASTransportEvt struct {
	RanUeNgapId int64
	Pdu         []byte
}

func (e *SendUplinkNASTransportEvt) Type() NgapEventType { return SendUplinkNASTransport }

func NewSendUplinkNASTransportEvt(ranUeNgapId int64, pdu []byte) *SendUplinkNASTransportEvt {
	return &SendUplinkNASTransportEvt{RanUeNgapId: ranUeNgapId, Pdu: pdu}
}

// SendInitialContextSetupRespEvt event
type SendInitialContextSetupRespEvt struct {
	RanUeNgapId            int64
	ResponseList           *ngapType.PDUSessionResourceSetupListCxtRes
	FailedList             *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	CriticalityDiagnostics *ngapType.CriticalityDiagnostics
}

func (e *SendInitialContextSetupRespEvt) Type() NgapEventType { return SendInitialContextSetupResponse }

func NewSendInitialContextSetupRespEvt(
	ranUeNgapId int64,
	responseList *ngapType.PDUSessionResourceSetupListCxtRes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) *SendInitialContextSetupRespEvt {
	return &SendInitialContextSetupRespEvt{
		RanUeNgapId:            ranUeNgapId,
		ResponseList:           responseList,
		FailedList:             failedList,
		CriticalityDiagnostics: criticalityDiagnostics,
	}
}

// SendUEContextReleaseEvt event
type SendUEContextReleaseEvt struct {
	RanUeNgapId int64
}

func (e *SendUEContextReleaseEvt) Type() NgapEventType { return SendUEContextRelease }

func NewSendUEContextReleaseEvt(ranUeNgapId int64) *SendUEContextReleaseEvt {
	return &SendUEContextReleaseEvt{RanUeNgapId: ranUeNgapId}
}

// SendPDUSessionResourceReleaseEvt event
type SendPDUSessionResourceReleaseEvt struct {
	RanUeNgapId  int64
	DeletePduIds []int64
}

func (e *SendPDUSessionResourceReleaseEvt) Type() NgapEventType { return SendPDUSessionResourceRelease }

func NewSendPDUSessionResourceReleaseEvt(ranUeNgapId int64, deletePduIds []int64) *SendPDUSessionResourceReleaseEvt {
	return &SendPDUSessionResourceReleaseEvt{RanUeNgapId: ranUeNgapId, DeletePduIds: deletePduIds}
}
