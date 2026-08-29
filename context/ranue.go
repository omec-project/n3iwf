// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"

	"github.com/omec-project/ngap/v2/ngapType"
)

// UeCtxRelState indicates UE Context release state
// NGAP has already received UE Context release command
// None: not ongoing, Ongoing: release in progress
// Use bool for performance, but type alias for clarity

type UeCtxRelState bool

const (
	UeCtxRelStateNone    UeCtxRelState = false
	UeCtxRelStateOngoing UeCtxRelState = true
)

// PduSessResRelState indicates PDU Session resource release state
// None: not ongoing, Ongoing: release in progress

type PduSessResRelState bool

const (
	PduSessResRelStateNone    PduSessResRelState = false
	PduSessResRelStateOngoing PduSessResRelState = true
)

// RanUe interface abstracts UE context operations

type RanUe interface {
	GetUserLocationInformation() *ngapType.UserLocationInformation
	GetSharedCtx() *RanUeSharedCtx
	CreatePDUSession(int64, ngapType.SNSSAI) (*PDUSession, error)
	DeletePDUSession(int64)
	FindPDUSession(int64) *PDUSession
	Remove() error
}

// RanUeSharedCtx holds shared context for a UE

type RanUeSharedCtx struct {
	PduSessionList                   map[int64]*PDUSession
	RadioCapability                  *ngapType.UERadioCapability
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformationForInactive
	AllowedNssai                     *ngapType.AllowedNSSAI
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	MaskedIMEISV                     *ngapType.MaskedIMEISV
	N3iwfCtx                         *N3IWFContext
	Guami                            *ngapType.GUAMI
	TemporaryPDUSessionSetupData     *PDUSessionSetupTemporaryData
	SecurityCapabilities             *ngapType.UESecurityCapabilities
	AMF                              *N3IWFAMF
	Guti                             string
	IPAddrv6                         string
	IPAddrv4                         string
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes
	AmfUeNgapId                      int64
	IndexToRfsp                      int64
	RanUeNgapId                      int64
	PortNumber                       int32
	IMSVoiceSupported                int32
	RRCEstablishmentCause            int16
	UeCtxRelState                    UeCtxRelState
	PduSessResRelState               PduSessResRelState
}

// PDUSession holds PDU session information

type PDUSession struct {
	Snssai                           ngapType.SNSSAI
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	NetworkInstance                  *ngapType.NetworkInstance
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QosFlows                         map[int64]*QosFlow
	QFIList                          []uint8
	Id                               int64
	SecurityCipher                   bool
	SecurityIntegrity                bool
}

// NewPDUSession returns a new PDUSession with initialized maps
func NewPDUSession(id int64, snssai ngapType.SNSSAI) *PDUSession {
	return &PDUSession{
		Id:       id,
		Snssai:   snssai,
		QosFlows: make(map[int64]*QosFlow),
	}
}

// QosFlow holds QoS flow information

type QosFlow struct {
	Parameters ngapType.QosFlowLevelQosParameters
	Identifier int64
}

// GTPConnectionInfo holds GTP connection details

type GTPConnectionInfo struct {
	UPFUDPAddr   net.Addr
	UPFIPAddr    string
	IncomingTEID uint32
	OutgoingTEID uint32
}

// PDUSessionSetupTemporaryData holds temporary data for PDU session setup

type PDUSessionSetupTemporaryData struct {
	SetupListCxtRes       *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes      *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes        *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes       *ngapType.PDUSessionResourceFailedToSetupListSURes
	UnactivatedPDUSession []*PDUSession
	FailedErrStr          []EvtError
	NGAPProcedureCode     ngapType.ProcedureCode
	Index                 int
}

// GetSharedCtx returns the shared context
func (ranUe *RanUeSharedCtx) GetSharedCtx() *RanUeSharedCtx {
	return ranUe
}

// FindPDUSession returns the PDU session for the given ID, or nil if not found
func (ranUe *RanUeSharedCtx) FindPDUSession(pduSessionID int64) *PDUSession {
	if pduSession, ok := ranUe.PduSessionList[pduSessionID]; ok {
		return pduSession
	}
	return nil
}

// CreatePDUSession creates a new PDU session if it does not exist
func (ranUe *RanUeSharedCtx) CreatePDUSession(pduSessionID int64, snssai ngapType.SNSSAI) (*PDUSession, error) {
	if _, exists := ranUe.PduSessionList[pduSessionID]; exists {
		return nil, fmt.Errorf("PDU Session[ID:%d] already exists", pduSessionID)
	}
	pduSession := NewPDUSession(pduSessionID, snssai)
	ranUe.PduSessionList[pduSessionID] = pduSession
	return pduSession, nil
}

// DeletePDUSession removes the PDU session for the given ID
func (ranUe *RanUeSharedCtx) DeletePDUSession(pduSessionId int64) {
	delete(ranUe.PduSessionList, pduSessionId)
}
