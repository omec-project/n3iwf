// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"net"
)

// IkeServer manages IKE UDP listeners and event channels
type IkeServer struct {
	RcvIkePktCh chan IkeReceivePacket
	RcvEventCh  chan IkeEvt
	StopServer  chan struct{}

	asyncEvents asyncSender[IkeEvt]
	listeners   socketRegistry[*net.UDPConn]
}

// RegisterListener records an open listener so that StopListeners closes it. It returns false
// if the server is already stopping, in which case the caller must close the listener itself.
func (s *IkeServer) RegisterListener(l *net.UDPConn) bool {
	return s.listeners.add(l)
}

// StopListeners returns the registered listeners for the caller to close, and makes later
// RegisterListener calls fail.
func (s *IkeServer) StopListeners() []*net.UDPConn {
	return s.listeners.shutdown()
}

// QueueEvent hands evt to the IKE event loop without ever blocking the caller. Use it from
// the NGAP event loop, so the two loops cannot deadlock on each other's full channels.
// Events queued this way are delivered in order and are never dropped.
func (s *IkeServer) QueueEvent(evt IkeEvt) {
	s.asyncEvents.send(s.RcvEventCh, evt)
}

// IkeReceivePacket represents a received IKE packet
// Use pointer types for efficiency
type IkeReceivePacket struct {
	Listener   *net.UDPConn
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	Msg        []byte
}

// IkeEventType enumerates IKE event types
type IkeEventType int64

const (
	UnmarshalEAP5GDataResponse IkeEventType = iota
	SendEAP5GFailureMsg
	SendEAPNASMsg
	SendEAPSuccessMsg
	CreatePDUSession
	IKEDeleteRequest
	SendChildSADeleteRequest
	IKEContextUpdate
	GetNGAPContextResponse
)

// IkeEvt is the interface for all IKE events
type IkeEvt interface {
	Type() IkeEventType
}

// UnmarshalEAP5GDataResponseEvt event
type UnmarshalEAP5GDataResponseEvt struct {
	NasPDU      []byte
	LocalSPI    uint64
	RanUeNgapId int64
}

func (e *UnmarshalEAP5GDataResponseEvt) Type() IkeEventType {
	return UnmarshalEAP5GDataResponse
}

func NewUnmarshalEAP5GDataResponseEvt(localSPI uint64, ranUeNgapId int64, nasPDU []byte) *UnmarshalEAP5GDataResponseEvt {
	return &UnmarshalEAP5GDataResponseEvt{
		LocalSPI:    localSPI,
		RanUeNgapId: ranUeNgapId,
		NasPDU:      nasPDU,
	}
}

// SendEAP5GFailureMsgEvt event
type SendEAP5GFailureMsgEvt struct {
	ErrMsg   EvtError
	LocalSPI uint64
}

func (e *SendEAP5GFailureMsgEvt) Type() IkeEventType {
	return SendEAP5GFailureMsg
}

func NewSendEAP5GFailureMsgEvt(localSPI uint64, errMsg EvtError) *SendEAP5GFailureMsgEvt {
	return &SendEAP5GFailureMsgEvt{
		LocalSPI: localSPI,
		ErrMsg:   errMsg,
	}
}

// SendEAPNASMsgEvt event
type SendEAPNASMsgEvt struct {
	NasPDU   []byte
	LocalSPI uint64
}

func (e *SendEAPNASMsgEvt) Type() IkeEventType {
	return SendEAPNASMsg
}

func NewSendEAPNASMsgEvt(localSPI uint64, nasPDU []byte) *SendEAPNASMsgEvt {
	return &SendEAPNASMsgEvt{
		LocalSPI: localSPI,
		NasPDU:   nasPDU,
	}
}

// SendEAPSuccessMsgEvt event
type SendEAPSuccessMsgEvt struct {
	Kn3iwf            []byte
	LocalSPI          uint64
	PduSessionListLen int
}

func (e *SendEAPSuccessMsgEvt) Type() IkeEventType {
	return SendEAPSuccessMsg
}

func NewSendEAPSuccessMsgEvt(localSPI uint64, kn3iwf []byte, pduSessionListLen int) *SendEAPSuccessMsgEvt {
	return &SendEAPSuccessMsgEvt{
		LocalSPI:          localSPI,
		Kn3iwf:            kn3iwf,
		PduSessionListLen: pduSessionListLen,
	}
}

// CreatePDUSessionEvt event
type CreatePDUSessionEvt struct {
	TempPDUSessionSetupData *PDUSessionSetupTemporaryData
	LocalSPI                uint64
	PduSessionListLen       int
}

func (e *CreatePDUSessionEvt) Type() IkeEventType {
	return CreatePDUSession
}

func NewCreatePDUSessionEvt(localSPI uint64, pduSessionListLen int, tempPDUSessionSetupData *PDUSessionSetupTemporaryData) *CreatePDUSessionEvt {
	return &CreatePDUSessionEvt{
		LocalSPI:                localSPI,
		PduSessionListLen:       pduSessionListLen,
		TempPDUSessionSetupData: tempPDUSessionSetupData,
	}
}

// IKEDeleteRequestEvt event
type IKEDeleteRequestEvt struct {
	LocalSPI uint64
}

func (e *IKEDeleteRequestEvt) Type() IkeEventType {
	return IKEDeleteRequest
}

func NewIKEDeleteRequestEvt(localSPI uint64) *IKEDeleteRequestEvt {
	return &IKEDeleteRequestEvt{
		LocalSPI: localSPI,
	}
}

// SendChildSADeleteRequestEvt event
type SendChildSADeleteRequestEvt struct {
	ReleaseIdList []int64
	LocalSPI      uint64
}

func (e *SendChildSADeleteRequestEvt) Type() IkeEventType {
	return SendChildSADeleteRequest
}

func NewSendChildSADeleteRequestEvt(localSPI uint64, releaseIdList []int64) *SendChildSADeleteRequestEvt {
	return &SendChildSADeleteRequestEvt{
		LocalSPI:      localSPI,
		ReleaseIdList: releaseIdList,
	}
}

// IKEContextUpdateEvt event
type IKEContextUpdateEvt struct {
	Kn3iwf   []byte
	LocalSPI uint64
}

func (e *IKEContextUpdateEvt) Type() IkeEventType {
	return IKEContextUpdate
}

func NewIKEContextUpdateEvt(localSPI uint64, kn3iwf []byte) *IKEContextUpdateEvt {
	return &IKEContextUpdateEvt{
		LocalSPI: localSPI,
		Kn3iwf:   kn3iwf,
	}
}

// GetNGAPContextRepEvt event
type GetNGAPContextRepEvt struct {
	NgapCxtReqNumlist []int64
	NgapCxt           []any
	LocalSPI          uint64
}

func (e *GetNGAPContextRepEvt) Type() IkeEventType {
	return GetNGAPContextResponse
}

func NewGetNGAPContextRepEvt(localSPI uint64, ngapCxtReqNumlist []int64, ngapCxt []any) *GetNGAPContextRepEvt {
	return &GetNGAPContextRepEvt{
		LocalSPI:          localSPI,
		NgapCxtReqNumlist: ngapCxtReqNumlist,
		NgapCxt:           ngapCxt,
	}
}
