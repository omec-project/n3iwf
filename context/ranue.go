// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"

	"github.com/omec-project/ngap/ngapType"
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
	// UE identity
	RanUeNgapId  int64
	AmfUeNgapId  int64
	IPAddrv4     string
	IPAddrv6     string
	PortNumber   int32
	MaskedIMEISV *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti         string

	// Relative Context
	N3iwfCtx *N3IWFContext
	AMF      *N3IWFAMF

	// Security
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86

	// PDU Session
	PduSessionList map[int64]*PDUSession // pduSessionId as key

	// PDU Session Setup Temporary Data
	TemporaryPDUSessionSetupData *PDUSessionSetupTemporaryData

	// Others
	Guami                            *ngapType.GUAMI
	IndexToRfsp                      int64
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	AllowedNssai                     *ngapType.AllowedNSSAI
	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                int32
	RRCEstablishmentCause            int16
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes
	UeCtxRelState                    UeCtxRelState
	PduSessResRelState               PduSessResRelState
}

// NewRanUeSharedCtx returns a new RanUeSharedCtx with initialized maps
func NewRanUeSharedCtx() *RanUeSharedCtx {
	return &RanUeSharedCtx{
		PduSessionList: make(map[int64]*PDUSession),
	}
}

// PDUSession holds PDU session information

type PDUSession struct {
	Id                               int64 // PDU Session ID
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai                           ngapType.SNSSAI
	NetworkInstance                  *ngapType.NetworkInstance
	SecurityCipher                   bool
	SecurityIntegrity                bool
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QFIList                          []uint8
	QosFlows                         map[int64]*QosFlow // QosFlowIdentifier as key
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
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

// GTPConnectionInfo holds GTP connection details

type GTPConnectionInfo struct {
	UPFIPAddr    string
	UPFUDPAddr   net.Addr
	IncomingTEID uint32
	OutgoingTEID uint32
}

// PDUSessionSetupTemporaryData holds temporary data for PDU session setup

type PDUSessionSetupTemporaryData struct {
	UnactivatedPDUSession []*PDUSession // Slice of unactivated PDU session
	NGAPProcedureCode     ngapType.ProcedureCode
	SetupListCxtRes       *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes      *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes        *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes       *ngapType.PDUSessionResourceFailedToSetupListSURes
	FailedErrStr          []EvtError // List of Error for failed setup PDUSessionID
	Index                 int        // Current Index of UnactivatedPDUSession
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
