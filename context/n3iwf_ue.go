// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2021 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"net"

	"github.com/omec-project/ngap/ngapConvert"
	"github.com/omec-project/ngap/ngapType"
)

// N3IWFRanUe represents a UE context in N3IWF
// Improved grouping and comments for clarity
type N3IWFRanUe struct {
	RanUeSharedCtx

	// NAS TCP Connection
	TCPConnection                   net.Conn
	IsNASTCPConnEstablished         bool
	IsNASTCPConnEstablishedComplete bool

	// Temporary cached NAS message used when NAS registration accept arrived
	// before UE setup NAS TCP connection with N3IWF, and forward
	// pduSessionEstablishmentAccept to UE after UE send CREATE_CHILD_SA response
	TemporaryCachedNASMessage []byte
}

// Initialize N3IWFRanUe context
func (n3iwfUe *N3IWFRanUe) init(ranUeNgapId int64) {
	n3iwfUe.RanUeNgapId = ranUeNgapId
	n3iwfUe.AmfUeNgapId = AmfUeNgapIdUnspecified
	n3iwfUe.PduSessionList = make(map[int64]*PDUSession)
	n3iwfUe.TemporaryPDUSessionSetupData = new(PDUSessionSetupTemporaryData)
	n3iwfUe.IsNASTCPConnEstablished = false
	n3iwfUe.IsNASTCPConnEstablishedComplete = false
}

// Remove cleans up UE context and associated resources
func (ranUe *N3IWFRanUe) Remove() error {
	// Remove from AMF context
	ranUe.DetachAMF()

	// Remove from RAN UE context
	n3iwfCtx := ranUe.N3iwfCtx
	n3iwfCtx.DeleteRanUe(ranUe.RanUeNgapId)

	// Delete all PDU session TEIDs
	for _, pduSession := range ranUe.PduSessionList {
		n3iwfCtx.DeleteTEID(pduSession.GTPConnection.IncomingTEID)
	}

	// Close TCP connection if exists
	if ranUe.TCPConnection == nil {
		return nil
	}
	if err := ranUe.TCPConnection.Close(); err != nil {
		return fmt.Errorf("close TCP conn error: %v", err)
	}
	return nil
}

// DetachAMF removes UE from AMF context
func (n3iwfUe *N3IWFRanUe) DetachAMF() {
	if n3iwfUe.AMF == nil {
		return
	}
	delete(n3iwfUe.AMF.N3iwfRanUeList, n3iwfUe.RanUeNgapId)
}

// GetUserLocationInformation returns UE location info for NGAP
func (n3iwfUe *N3IWFRanUe) GetUserLocationInformation() *ngapType.UserLocationInformation {
	userLocationInformation := new(ngapType.UserLocationInformation)
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationN3IWF
	userLocationInformation.UserLocationInformationN3IWF = new(ngapType.UserLocationInformationN3IWF)

	userLocationInfoN3IWF := userLocationInformation.UserLocationInformationN3IWF
	userLocationInfoN3IWF.IPAddress = ngapConvert.IPAddressToNgap(n3iwfUe.IPAddrv4, n3iwfUe.IPAddrv6)
	userLocationInfoN3IWF.PortNumber = ngapConvert.PortNumberToNgap(n3iwfUe.PortNumber)

	return userLocationInformation
}
