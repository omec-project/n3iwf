// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/ngap/aper"
	"github.com/omec-project/ngap/ngapConvert"
	"github.com/omec-project/ngap/ngapType"
	"github.com/wmnsk/go-gtp/gtpv1"
)

var (
	defaultSecurityIntegrity bool = true
	defaultSecurityCipher    bool = true
)

func HandleNGSetupResponse(sctpAddr string, conn *sctp.SCTPConn, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Setup Response")

	var amfName *ngapType.AMFName
	var servedGUAMIList *ngapType.ServedGUAMIList
	var relativeAMFCapacity *ngapType.RelativeAMFCapacity
	var plmnSupportList *ngapType.PLMNSupportList
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := pdu.SuccessfulOutcome
	if successfulOutcome == nil {
		logger.NgapLog.Errorln("successful Outcome is nil")
		return
	}

	ngSetupResponse := successfulOutcome.Value.NGSetupResponse
	if ngSetupResponse == nil {
		logger.NgapLog.Errorln("ngSetupResponse is nil")
		return
	}

	for _, ie := range ngSetupResponse.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			logger.NgapLog.Debugln("decode IE AMFName")
			amfName = ie.Value.AMFName
			if amfName == nil {
				logger.NgapLog.Errorln("AMFName is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDServedGUAMIList:
			logger.NgapLog.Debugln("decode IE ServedGUAMIList")
			servedGUAMIList = ie.Value.ServedGUAMIList
			if servedGUAMIList == nil {
				logger.NgapLog.Errorln("ServedGUAMIList is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			logger.NgapLog.Debugln("decode IE RelativeAMFCapacity")
			relativeAMFCapacity = ie.Value.RelativeAMFCapacity
		case ngapType.ProtocolIEIDPLMNSupportList:
			logger.NgapLog.Debugln("decode IE PLMNSupportList")
			plmnSupportList = ie.Value.PLMNSupportList
			if plmnSupportList == nil {
				logger.NgapLog.Errorln("PLMNSupportList is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	if len(iesCriticalityDiagnostics.List) != 0 {
		logger.NgapLog.Debugln("sending error indication to AMF, because some mandatory IEs were not included")

		cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		procedureCode := ngapType.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentSuccessfulOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)

		return
	}

	amfInfo := n3iwfCtx.NewN3iwfAmf(sctpAddr, conn)

	if amfName != nil {
		amfInfo.AMFName = amfName
	}

	if servedGUAMIList != nil {
		amfInfo.ServedGUAMIList = servedGUAMIList
	}

	if relativeAMFCapacity != nil {
		amfInfo.RelativeAMFCapacity = relativeAMFCapacity
	}

	if plmnSupportList != nil {
		amfInfo.PLMNSupportList = plmnSupportList
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
}

func HandleNGSetupFailure(sctpAddr string, conn *sctp.SCTPConn, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Setup Failure")

	var cause *ngapType.Cause
	var timeToWait *ngapType.TimeToWait
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	if unsuccessfulOutcome == nil {
		logger.NgapLog.Errorln("unsuccessful Message is nil")
		return
	}

	ngSetupFailure := unsuccessfulOutcome.Value.NGSetupFailure
	if ngSetupFailure == nil {
		logger.NgapLog.Errorln("NGSetupFailure is nil")
		return
	}

	for _, ie := range ngSetupFailure.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			logger.NgapLog.Debugln("decode IE Cause")
			cause = ie.Value.Cause
			if cause == nil {
				logger.NgapLog.Errorln("cause is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDTimeToWait:
			logger.NgapLog.Debugln("decode IE TimeToWait")
			timeToWait = ie.Value.TimeToWait
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: Send error indication
		logger.NgapLog.Debugln("sending error indication to AMF, because some mandatory IEs were not included")

		cause = message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		procedureCode := ngapType.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentUnsuccessfullOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)

		return
	}

	printAndGetCause(cause)

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	var waitingTime int

	if timeToWait != nil {
		switch timeToWait.Value {
		case ngapType.TimeToWaitPresentV1s:
			waitingTime = 1
		case ngapType.TimeToWaitPresentV2s:
			waitingTime = 2
		case ngapType.TimeToWaitPresentV5s:
			waitingTime = 5
		case ngapType.TimeToWaitPresentV10s:
			waitingTime = 10
		case ngapType.TimeToWaitPresentV20s:
			waitingTime = 20
		case ngapType.TimeToWaitPresentV60s:
			waitingTime = 60
		}
	}

	if waitingTime != 0 {
		logger.NgapLog.Infof("wait at lease  %ds to reinitialize with same AMF[%s]", waitingTime, sctpAddr)
		n3iwfCtx.AMFReInitAvailableListStore(sctpAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			n3iwfCtx.AMFReInitAvailableListStore(sctpAddr, true)
			message.SendNGSetupRequest(conn, n3iwfCtx)
		})
		return
	}
}

func HandleNGReset(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Reset")

	var cause *ngapType.Cause
	var resetType *ngapType.ResetType
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfCtx := context.N3IWFSelf()

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("InitiatingMessage is nil")
		return
	}

	nGReset := initiatingMessage.Value.NGReset
	if nGReset == nil {
		logger.NgapLog.Errorln("nGReset is nil")
		return
	}

	for _, ie := range nGReset.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			logger.NgapLog.Debugln("decode IE Cause")
			cause = ie.Value.Cause
		case ngapType.ProtocolIEIDResetType:
			logger.NgapLog.Debugln("decode IE ResetType")
			resetType = ie.Value.ResetType
			if resetType == nil {
				logger.NgapLog.Errorln("ResetType is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapType.ProcedureCodeNGReset
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	printAndGetCause(cause)

	switch resetType.Present {
	case ngapType.ResetTypePresentNGInterface:
		logger.NgapLog.Debugln("ResetType Present: NG Interface")
		// TODO: Release Uu Interface related to this amf(IPSec)
		// Remove all Ue
		if err := amf.RemoveAllRelatedUe(); err != nil {
			logger.NgapLog.Errorf("remove all related UE error: %+v", err)
		}
		message.SendNGResetAcknowledge(amf, nil, nil)
	case ngapType.ResetTypePresentPartOfNGInterface:
		logger.NgapLog.Debugln("ResetType Present: Part of NG Interface")

		partOfNGInterface := resetType.PartOfNGInterface
		if partOfNGInterface == nil {
			logger.NgapLog.Errorln("PartOfNGInterface is nil")
			return
		}

		var ranUe context.RanUe

		for _, ueAssociatedLogicalNGConnectionItem := range partOfNGInterface.List {
			if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
				logger.NgapLog.Debugf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				ranUe, _ = n3iwfCtx.RanUePoolLoad(ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
			} else if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
				logger.NgapLog.Debugf("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				ranUe = amf.FindUeByAmfUeNgapID(ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
			}

			if ranUe == nil {
				logger.NgapLog.Warnln("cannot not find RanUE Context")
				if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
					logger.NgapLog.Warnf("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				}
				if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
					logger.NgapLog.Warnf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				}
				continue
			}
			// TODO: Release Uu Interface (IPSec)
			if err := ranUe.Remove(); err != nil {
				logger.NgapLog.Errorf("remove RanUE context error: %+v", err)
			}
		}
		message.SendNGResetAcknowledge(amf, partOfNGInterface, nil)
	default:
		logger.NgapLog.Warnf("invalid ResetType[%d]", resetType.Present)
	}
}

func HandleNGResetAcknowledge(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Reset Acknowledge")

	var uEAssociatedLogicalNGConnectionList *ngapType.UEAssociatedLogicalNGConnectionList
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := pdu.SuccessfulOutcome
	if successfulOutcome == nil {
		logger.NgapLog.Errorln("successfulOutcome is nil")
		return
	}

	nGResetAcknowledge := successfulOutcome.Value.NGResetAcknowledge
	if nGResetAcknowledge == nil {
		logger.NgapLog.Errorln("nGResetAcknowledge is nil")
		return
	}

	for _, ie := range nGResetAcknowledge.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList:
			logger.NgapLog.Debugln("decode IE UEAssociatedLogicalNGConnectionList")
			uEAssociatedLogicalNGConnectionList = ie.Value.UEAssociatedLogicalNGConnectionList
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	if uEAssociatedLogicalNGConnectionList != nil {
		logger.NgapLog.Debugf("%d RanUE association(s) has been reset", len(uEAssociatedLogicalNGConnectionList.List))
		for i, item := range uEAssociatedLogicalNGConnectionList.List {
			if item.AMFUENGAPID != nil && item.RANUENGAPID != nil {
				logger.NgapLog.Debugf("%d: AmfUeNgapID[%d] RanUeNgapID[%d]",
					i+1, item.AMFUENGAPID.Value, item.RANUENGAPID.Value)
			} else if item.AMFUENGAPID != nil {
				logger.NgapLog.Debugf("%d: AmfUeNgapID[%d] RanUeNgapID[unknown]", i+1, item.AMFUENGAPID.Value)
			} else if item.RANUENGAPID != nil {
				logger.NgapLog.Debugf("%d: AmfUeNgapID[unknown] RanUeNgapID[%d]", i+1, item.RANUENGAPID.Value)
			}
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
}

func HandleInitialContextSetupRequest(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Initial Context Setup Request")

	var amfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var oldAMF *ngapType.AMFName
	var ueAggregateMaximumBitRate *ngapType.UEAggregateMaximumBitRate
	var coreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation
	var guami *ngapType.GUAMI
	var pduSessionResourceSetupListCxtReq *ngapType.PDUSessionResourceSetupListCxtReq
	var allowedNSSAI *ngapType.AllowedNSSAI
	var ueSecurityCapabilities *ngapType.UESecurityCapabilities
	var securityKey *ngapType.SecurityKey
	var traceActivation *ngapType.TraceActivation
	var ueRadioCapability *ngapType.UERadioCapability
	var indexToRFSP *ngapType.IndexToRFSP
	var maskedIMEISV *ngapType.MaskedIMEISV
	// var nasPDU *ngapType.NASPDU
	var emergencyFallbackIndicator *ngapType.EmergencyFallbackIndicator
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var ranUe context.RanUe
	var ranUeCtx *context.RanUeSharedCtx

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("Initiating Message is nil")
		return
	}

	initialContextSetupRequest := initiatingMessage.Value.InitialContextSetupRequest
	if initialContextSetupRequest == nil {
		logger.NgapLog.Errorln("InitialContextSetupRequest is nil")
		return
	}

	for _, ie := range initialContextSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			amfUeNgapID = ie.Value.AMFUENGAPID
			if amfUeNgapID == nil {
				logger.NgapLog.Errorf("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			ranUeNgapID = ie.Value.RANUENGAPID
			if ranUeNgapID == nil {
				logger.NgapLog.Errorf("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDOldAMF:
			logger.NgapLog.Debugln("decode IE OldAMF")
			oldAMF = ie.Value.OldAMF
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			logger.NgapLog.Debugln("decode IE UEAggregateMaximumBitRate")
			ueAggregateMaximumBitRate = ie.Value.UEAggregateMaximumBitRate
		case ngapType.ProtocolIEIDCoreNetworkAssistanceInformation:
			logger.NgapLog.Debugln("decode IE CoreNetworkAssistanceInformation")
			coreNetworkAssistanceInformation = ie.Value.CoreNetworkAssistanceInformation
			if coreNetworkAssistanceInformation != nil {
				logger.NgapLog.Warnln("not Supported IE [CoreNetworkAssistanceInformation]")
			}
		case ngapType.ProtocolIEIDGUAMI:
			logger.NgapLog.Debugln("decode IE GUAMI")
			guami = ie.Value.GUAMI
			if guami == nil {
				logger.NgapLog.Errorf("GUAMI is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceSetupListCxtReq")
			pduSessionResourceSetupListCxtReq = ie.Value.PDUSessionResourceSetupListCxtReq
		case ngapType.ProtocolIEIDAllowedNSSAI:
			logger.NgapLog.Debugln("decode IE AllowedNSSAI")
			allowedNSSAI = ie.Value.AllowedNSSAI
			if allowedNSSAI == nil {
				logger.NgapLog.Errorf("AllowedNSSAI is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDUESecurityCapabilities:
			logger.NgapLog.Debugln("decode IE UESecurityCapabilities")
			ueSecurityCapabilities = ie.Value.UESecurityCapabilities
			if ueSecurityCapabilities == nil {
				logger.NgapLog.Errorf("UESecurityCapabilities is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDSecurityKey:
			logger.NgapLog.Debugln("decode IE SecurityKey")
			securityKey = ie.Value.SecurityKey
			if securityKey == nil {
				logger.NgapLog.Errorln("SecurityKey is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDTraceActivation:
			logger.NgapLog.Debugln("decode IE TraceActivation")
			traceActivation = ie.Value.TraceActivation
			if traceActivation != nil {
				logger.NgapLog.Warnln("not Supported IE [TraceActivation]")
			}
		case ngapType.ProtocolIEIDUERadioCapability:
			logger.NgapLog.Debugln("decode IE UERadioCapability")
			ueRadioCapability = ie.Value.UERadioCapability
		case ngapType.ProtocolIEIDIndexToRFSP:
			logger.NgapLog.Debugln("decode IE IndexToRFSP")
			indexToRFSP = ie.Value.IndexToRFSP
		case ngapType.ProtocolIEIDMaskedIMEISV:
			logger.NgapLog.Debugln("decode IE MaskedIMEISV")
			maskedIMEISV = ie.Value.MaskedIMEISV
		case ngapType.ProtocolIEIDNASPDU:
			logger.NgapLog.Debugln("decode IE NAS PDU")
			// nasPDU = ie.Value.NASPDU
		case ngapType.ProtocolIEIDEmergencyFallbackIndicator:
			logger.NgapLog.Debugln("decode IE EmergencyFallbackIndicator")
			emergencyFallbackIndicator = ie.Value.EmergencyFallbackIndicator
			if emergencyFallbackIndicator != nil {
				logger.NgapLog.Warnln("not Supported IE [EmergencyFallbackIndicator]")
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		logger.NgapLog.Debugln("sending unsuccessful outcome to AMF, because some mandatory IEs were not included")
		cause := message.BuildCause(ngapType.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

		failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
		for _, item := range pduSessionResourceSetupListCxtReq.List {
			transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			message.AppendPDUSessionResourceFailedToSetupListCxtfail(
				failedListCxtFail, item.PDUSessionID.Value, transfer)
		}

		message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if ranUe == nil {
		logger.NgapLog.Errorln("RAN UE context is nil")
		return
	}

	ranUeCtx.AmfUeNgapId = amfUeNgapID.Value
	ranUeCtx.RanUeNgapId = ranUeNgapID.Value

	if pduSessionResourceSetupListCxtReq != nil {
		if ueAggregateMaximumBitRate == nil {
			logger.NgapLog.Errorln("IE[UEAggregateMaximumBitRate] is nil")
			cause := message.BuildCause(ngapType.CausePresentProtocol,
				ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

			criticalityDiagnosticsIEItem := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject,
				ngapType.ProtocolIEIDUEAggregateMaximumBitRate, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, criticalityDiagnosticsIEItem)
			criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

			failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
			for _, item := range pduSessionResourceSetupListCxtReq.List {
				transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				message.AppendPDUSessionResourceFailedToSetupListCxtfail(
					failedListCxtFail, item.PDUSessionID.Value, transfer)
			}

			message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
			return
		}
		ranUeCtx.Ambr = ueAggregateMaximumBitRate

		setupListCxtRes := new(ngapType.PDUSessionResourceSetupListCxtRes)
		failedListCxtRes := new(ngapType.PDUSessionResourceFailedToSetupListCxtRes)

		// UE temporary data for PDU session setup response
		ranUeCtx.TemporaryPDUSessionSetupData.SetupListCxtRes = setupListCxtRes
		ranUeCtx.TemporaryPDUSessionSetupData.FailedListCxtRes = failedListCxtRes
		ranUeCtx.TemporaryPDUSessionSetupData.Index = 0
		ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession = nil
		ranUeCtx.TemporaryPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup

		for _, item := range pduSessionResourceSetupListCxtReq.List {
			pduSessionID := item.PDUSessionID.Value
			// TODO: send NAS to UE
			// pduSessionNasPdu := item.NASPDU
			snssai := item.SNSSAI

			transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
			err := aper.UnmarshalWithParams(item.PDUSessionResourceSetupRequestTransfer, &transfer, "valueExt")
			if err != nil {
				logger.NgapLog.Errorf("[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %+v",
					pduSessionID, err)
			}

			pduSession, err := ranUeCtx.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := message.BuildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				message.AppendPDUSessionResourceFailedToSetupListCxtRes(
					failedListCxtRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession = append(
					ranUeCtx.TemporaryPDUSessionSetupData.UnactivatedPDUSession, pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUeCtx.PduSessionList, pduSessionID)
				message.AppendPDUSessionResourceFailedToSetupListCxtRes(failedListCxtRes, pduSessionID, resTransfer)
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if guami != nil {
		ranUeCtx.Guami = guami
	}

	if allowedNSSAI != nil {
		ranUeCtx.AllowedNssai = allowedNSSAI
	}

	if maskedIMEISV != nil {
		ranUeCtx.MaskedIMEISV = maskedIMEISV
	}

	if ueRadioCapability != nil {
		ranUeCtx.RadioCapability = ueRadioCapability
	}

	if coreNetworkAssistanceInformation != nil {
		ranUeCtx.CoreNetworkAssistanceInformation = coreNetworkAssistanceInformation
	}

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	if ueSecurityCapabilities != nil {
		ranUeCtx.SecurityCapabilities = ueSecurityCapabilities
	}

	// Send EAP Success to UE
	switch ue := ranUe.(type) {
	case *context.N3IWFRanUe:
		spi, ok := n3iwfCtx.IkeSpiLoad(ranUeCtx.RanUeNgapId)
		if !ok {
			logger.NgapLog.Errorf("cannot get spi from ngapid: %d", ranUeCtx.RanUeNgapId)
			return
		}

		n3iwfCtx.IkeServer.RcvEventCh <- context.NewSendEAPSuccessMsgEvt(spi, securityKey.Value.Bytes, len(ranUeCtx.PduSessionList))
	default:
		logger.NgapLog.Errorf("unknown UE type: %T", ue)
	}
}

// handlePDUSessionResourceSetupRequestTransfer parse and store needed information from NGAP
// and setup user plane connection for UE
// Parameters:
// UE context :: a pointer to the UE's pdusession data structure ::
// SMF PDU session resource setup request transfer
// Return value:
// a status value indicates whether the handling is "success" ::
// if failed, an unsuccessfulTransfer is set, otherwise, set to nil
func handlePDUSessionResourceSetupRequestTransfer(ranUe context.RanUe, pduSession *context.PDUSession,
	transfer ngapType.PDUSessionResourceSetupRequestTransfer,
) (bool, []byte) {
	var pduSessionAMBR *ngapType.PDUSessionAggregateMaximumBitRate
	var ulNGUUPTNLInformation *ngapType.UPTransportLayerInformation
	var pduSessionType *ngapType.PDUSessionType
	var securityIndication *ngapType.SecurityIndication
	var networkInstance *ngapType.NetworkInstance
	var qosFlowSetupRequestList *ngapType.QosFlowSetupRequestList
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	for _, ie := range transfer.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate:
			pduSessionAMBR = ie.Value.PDUSessionAggregateMaximumBitRate
		case ngapType.ProtocolIEIDULNGUUPTNLInformation:
			ulNGUUPTNLInformation = ie.Value.ULNGUUPTNLInformation
			if ulNGUUPTNLInformation == nil {
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDPDUSessionType:
			pduSessionType = ie.Value.PDUSessionType
			if pduSessionType == nil {
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDSecurityIndication:
			securityIndication = ie.Value.SecurityIndication
		case ngapType.ProtocolIEIDNetworkInstance:
			networkInstance = ie.Value.NetworkInstance
		case ngapType.ProtocolIEIDQosFlowSetupRequestList:
			qosFlowSetupRequestList = ie.Value.QosFlowSetupRequestList
			if qosFlowSetupRequestList == nil {
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		cause := message.BuildCause(ngapType.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, &criticalityDiagnostics)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
		}
		return false, responseTransfer
	}

	pduSession.Ambr = pduSessionAMBR
	pduSession.Type = pduSessionType
	pduSession.NetworkInstance = networkInstance

	// Security Indication
	if securityIndication != nil {
		switch securityIndication.IntegrityProtectionIndication.Value {
		case ngapType.IntegrityProtectionIndicationPresentNotNeeded:
			pduSession.SecurityIntegrity = !defaultSecurityIntegrity
		case ngapType.IntegrityProtectionIndicationPresentPreferred:
			pduSession.SecurityIntegrity = defaultSecurityIntegrity
		case ngapType.IntegrityProtectionIndicationPresentRequired:
			pduSession.SecurityIntegrity = defaultSecurityIntegrity
		default:
			logger.NgapLog.Errorln("unknown security integrity indication")
			cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}

		switch securityIndication.ConfidentialityProtectionIndication.Value {
		case ngapType.ConfidentialityProtectionIndicationPresentNotNeeded:
			pduSession.SecurityCipher = !defaultSecurityCipher
		case ngapType.ConfidentialityProtectionIndicationPresentPreferred:
			pduSession.SecurityCipher = defaultSecurityCipher
		case ngapType.ConfidentialityProtectionIndicationPresentRequired:
			pduSession.SecurityCipher = defaultSecurityCipher
		default:
			logger.NgapLog.Errorln("unknown security confidentiality indication")
			cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}
	} else {
		pduSession.SecurityIntegrity = defaultSecurityIntegrity
		pduSession.SecurityCipher = defaultSecurityCipher
	}

	// TODO: apply qos rule
	for _, item := range qosFlowSetupRequestList.List {
		// QoS Flow
		qosFlow := new(context.QosFlow)
		qosFlow.Identifier = item.QosFlowIdentifier.Value
		qosFlow.Parameters = item.QosFlowLevelQosParameters
		pduSession.QosFlows[item.QosFlowIdentifier.Value] = qosFlow

		value := item.QosFlowIdentifier.Value
		if value < 0 || value > math.MaxUint8 {
			logger.NgapLog.Errorf("item.QosFlowIdentifier.Value exceeds uint8 range: %d", value)
			cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer error: %+v", err)
			}
			return false, responseTransfer
		}
		// QFI List
		pduSession.QFIList = append(pduSession.QFIList, uint8(value))
	}

	// Setup GTP tunnel with UPF
	// TODO: Support IPv6
	upfIPv4, _ := ngapConvert.IPAddressToString(ulNGUUPTNLInformation.GTPTunnel.TransportLayerAddress)
	if upfIPv4 == "" {
		logger.NgapLog.Errorln("cannot parse 'PDU session resource setup request transfer' message 'UL NG-U UP TNL Information'")
		cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		responseTransfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
		}
		return false, responseTransfer
	}

	n3iwfCtx := context.N3IWFSelf()

	gtpConnection := &context.GTPConnectionInfo{
		UPFIPAddr:    upfIPv4,
		OutgoingTEID: binary.BigEndian.Uint32(ulNGUUPTNLInformation.GTPTunnel.GTPTEID.Value),
	}

	// UPF UDP address
	upfAddr := upfIPv4 + gtpv1.GTPUPort
	upfUDPAddr, err := net.ResolveUDPAddr("udp", upfAddr)
	if err != nil {
		var responseTransfer []byte

		logger.NgapLog.Errorf("resolve UPF addr [%s] failed: %v", upfAddr, err)
		cause := message.BuildCause(ngapType.CausePresentTransport,
			ngapType.CauseTransportPresentTransportResourceUnavailable)
		responseTransfer, err = message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer error: %+v", err)
		}
		return false, responseTransfer
	}

	// UE TEID
	ueTEID := n3iwfCtx.NewTEID(ranUe)
	if ueTEID == 0 {
		var responseTransfer []byte

		logger.NgapLog.Error("invalid TEID (0)")
		cause := message.BuildCause(
			ngapType.CausePresentProtocol,
			ngapType.CauseProtocolPresentUnspecified)
		responseTransfer, err = message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer error: %+v", err)
		}
		return false, responseTransfer
	}

	// Setup GTP connection with UPF
	gtpConnection.UPFUDPAddr = upfUDPAddr
	gtpConnection.IncomingTEID = ueTEID

	pduSession.GTPConnection = gtpConnection

	return true, nil
}

func HandleUEContextModificationRequest(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE Context Modification Request")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var amfUeNgapID *ngapType.AMFUENGAPID
	var newAmfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var ueAggregateMaximumBitRate *ngapType.UEAggregateMaximumBitRate
	var ueSecurityCapabilities *ngapType.UESecurityCapabilities
	var securityKey *ngapType.SecurityKey
	var indexToRFSP *ngapType.IndexToRFSP
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var ranUe context.RanUe
	var ranUeCtx *context.RanUeSharedCtx

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	ueContextModificationRequest := initiatingMessage.Value.UEContextModificationRequest
	if ueContextModificationRequest == nil {
		logger.NgapLog.Errorln("UEContextModificationRequest is nil")
		return
	}

	for _, ie := range ueContextModificationRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			amfUeNgapID = ie.Value.AMFUENGAPID
			if amfUeNgapID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			ranUeNgapID = ie.Value.RANUENGAPID
			if ranUeNgapID == nil {
				logger.NgapLog.Errorf("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDSecurityKey:
			logger.NgapLog.Debugln("decode IE SecurityKey")
			securityKey = ie.Value.SecurityKey
		case ngapType.ProtocolIEIDIndexToRFSP:
			logger.NgapLog.Debugln("decode IE IndexToRFSP")
			indexToRFSP = ie.Value.IndexToRFSP
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			logger.NgapLog.Debugln("decode IE UEAggregateMaximumBitRate")
			ueAggregateMaximumBitRate = ie.Value.UEAggregateMaximumBitRate
		case ngapType.ProtocolIEIDUESecurityCapabilities:
			logger.NgapLog.Debugln("decode IE UESecurityCapabilities")
			ueSecurityCapabilities = ie.Value.UESecurityCapabilities
		case ngapType.ProtocolIEIDCoreNetworkAssistanceInformation:
			logger.NgapLog.Debugln("decode IE CoreNetworkAssistanceInformation")
			logger.NgapLog.Warnln("not Supported IE [CoreNetworkAssistanceInformation]")
		case ngapType.ProtocolIEIDEmergencyFallbackIndicator:
			logger.NgapLog.Debugln("decode IE EmergencyFallbackIndicator")
			logger.NgapLog.Warnln("not Supported IE [EmergencyFallbackIndicator]")
		case ngapType.ProtocolIEIDNewAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE NewAMFUENGAPID")
			newAmfUeNgapID = ie.Value.NewAMFUENGAPID
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: send unsuccessful outcome or error indication
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if newAmfUeNgapID != nil {
		logger.NgapLog.Debugf("new AmfUeNgapID[%d]", newAmfUeNgapID.Value)
		ranUeCtx.AmfUeNgapId = newAmfUeNgapID.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUeCtx.Ambr = ueAggregateMaximumBitRate
		// TODO: use the received UE Aggregate Maximum Bit Rate for all non-GBR QoS flows
	}

	if ueSecurityCapabilities != nil {
		ranUeCtx.SecurityCapabilities = ueSecurityCapabilities
	}

	// TODO: use new security key to update security context

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	message.SendUEContextModificationResponse(ranUe, nil)

	spi, ok := n3iwfCtx.IkeSpiLoad(ranUeCtx.RanUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get spi from ngapid: %d", ranUeCtx.RanUeNgapId)
		return
	}

	n3iwfCtx.IkeServer.RcvEventCh <- context.NewIKEContextUpdateEvt(spi, securityKey.Value.Bytes) // Kn3iwf
}

func HandleUEContextReleaseCommand(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE Context Release Command")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var ueNgapIDs *ngapType.UENGAPIDs
	var cause *ngapType.Cause
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe context.RanUe

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	ueContextReleaseCommand := initiatingMessage.Value.UEContextReleaseCommand
	if ueContextReleaseCommand == nil {
		logger.NgapLog.Errorln("UEContextReleaseCommand is nil")
		return
	}

	for _, ie := range ueContextReleaseCommand.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUENGAPIDs:
			logger.NgapLog.Debugln("decode IE UENGAPIDs")
			ueNgapIDs = ie.Value.UENGAPIDs
			if ueNgapIDs == nil {
				logger.NgapLog.Errorln("UENGAPIDs is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDCause:
			logger.NgapLog.Debugln("decode IE Cause")
			cause = ie.Value.Cause
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: send error indication
		return
	}

	switch ueNgapIDs.Present {
	case ngapType.UENGAPIDsPresentUENGAPIDPair:
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ueNgapIDs.UENGAPIDPair.RANUENGAPID.Value)
		if !ok {
			ranUe = amf.FindUeByAmfUeNgapID(ueNgapIDs.UENGAPIDPair.AMFUENGAPID.Value)
		}
	case ngapType.UENGAPIDsPresentAMFUENGAPID:
		// TODO: find UE according to specific AMF
		// The implementation here may have error when N3IWF need to
		// connect multiple AMFs.
		// Use UEpool in AMF context can solve this problem
		ranUe = amf.FindUeByAmfUeNgapID(ueNgapIDs.AMFUENGAPID.Value)
	}

	if ranUe == nil {
		// TODO: send error indication(unknown local ngap ue id)
		return
	}

	printAndGetCause(cause)

	ranUe.GetSharedCtx().UeCtxRelState = context.UeCtxRelStateOngoing

	message.SendUEContextReleaseComplete(ranUe, nil)

	err := releaseIkeUeAndRanUe(ranUe)
	if err != nil {
		logger.NgapLog.Warnf("HandleUEContextReleaseCommand(): %v", err)
	}
}

func releaseIkeUeAndRanUe(ranUe context.RanUe) error {
	n3iwfCtx := context.N3IWFSelf()
	ranUeNgapID := ranUe.GetSharedCtx().RanUeNgapId

	if localSPI, ok := n3iwfCtx.IkeSpiLoad(ranUeNgapID); ok {
		n3iwfCtx.IkeServer.RcvEventCh <- context.NewIKEDeleteRequestEvt(localSPI)
	}

	if err := ranUe.Remove(); err != nil {
		return fmt.Errorf("releaseIkeUeAndRanUe: failed to remove RanUeNgapId[%016x]: %w", ranUeNgapID, err)
	}
	return nil
}

func encapNasMsgToEnvelope(nasPDU *ngapType.NASPDU) []byte {
	// According to TS 24.502 8.2.4, in order to transport a NAS message over the
	// non-3GPP access between the UE and the N3IWF, the NAS message shall be
	// framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4, a NAS message envelope = Length | NAS Message
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU.Value)))
	nasEnv = append(nasEnv, nasPDU.Value...)
	return nasEnv
}

func HandleDownlinkNASTransport(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Downlink NAS Transport")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var amfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var oldAMF *ngapType.AMFName
	var nasPDU *ngapType.NASPDU
	var indexToRFSP *ngapType.IndexToRFSP
	var ueAggregateMaximumBitRate *ngapType.UEAggregateMaximumBitRate
	var allowedNSSAI *ngapType.AllowedNSSAI
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe context.RanUe

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	downlinkNASTransport := initiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		logger.NgapLog.Errorln("DownlinkNASTransport is nil")
		return
	}

	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			amfUeNgapID = ie.Value.AMFUENGAPID
			if amfUeNgapID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			ranUeNgapID = ie.Value.RANUENGAPID
			if ranUeNgapID == nil {
				logger.NgapLog.Errorln("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDOldAMF:
			logger.NgapLog.Debugln("decode IE OldAMF")
			oldAMF = ie.Value.OldAMF
		case ngapType.ProtocolIEIDNASPDU:
			logger.NgapLog.Debugln("decode IE NASPDU")
			nasPDU = ie.Value.NASPDU
			if nasPDU == nil {
				logger.NgapLog.Errorln("NASPDU is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDIndexToRFSP:
			logger.NgapLog.Debugln("decode IE IndexToRFSP")
			indexToRFSP = ie.Value.IndexToRFSP
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			logger.NgapLog.Debugln("decode IE UEAggregateMaximumBitRate")
			ueAggregateMaximumBitRate = ie.Value.UEAggregateMaximumBitRate
		case ngapType.ProtocolIEIDAllowedNSSAI:
			logger.NgapLog.Debugln("decode IE AllowedNSSAI")
			allowedNSSAI = ie.Value.AllowedNSSAI
		}
	}

	// if len(iesCriticalityDiagnostics.List) > 0 {
	// TODO: Send Error Indication
	// }

	if ranUeNgapID != nil {
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Warnf("no UE Context[RanUeNgapID:%d]", ranUeNgapID.Value)
			return
		}
	}
	ranUeCtx := ranUe.GetSharedCtx()

	if amfUeNgapID != nil {
		if ranUeCtx.AmfUeNgapId == context.AmfUeNgapIdUnspecified {
			logger.NgapLog.Debugln("create new logical UE-associated NG-connection")
			ranUeCtx.AmfUeNgapId = amfUeNgapID.Value
		} else {
			if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
				logger.NgapLog.Warnln("AMFUENGAPID unmatched")
				return
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if indexToRFSP != nil {
		ranUeCtx.IndexToRfsp = indexToRFSP.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUeCtx.Ambr = ueAggregateMaximumBitRate
	}

	if allowedNSSAI != nil {
		ranUeCtx.AllowedNssai = allowedNSSAI
	}

	if nasPDU != nil {
		switch ue := ranUe.(type) {
		case *context.N3IWFRanUe:
			// Send EAP5G NAS to UE
			spi, ok := n3iwfCtx.IkeSpiLoad(ue.RanUeNgapId)
			if !ok {
				logger.NgapLog.Errorf("cannot get SPI from RanUeNGAPId: %d", ue.RanUeNgapId)
				return
			}

			if !ue.IsNASTCPConnEstablished {
				n3iwfCtx.IkeServer.RcvEventCh <- context.NewSendEAPNASMsgEvt(spi, []byte(nasPDU.Value))
			} else {
				// Using a "NAS message envelope" to transport a NAS message
				// over the non-3GPP access between the UE and the N3IWF
				nasEnv := encapNasMsgToEnvelope(nasPDU)

				if ue.IsNASTCPConnEstablishedComplete {
					// Send to UE
					if n, err := ue.TCPConnection.Write(nasEnv); err != nil {
						logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %v", err)
					} else {
						logger.NgapLog.Debugln("forward NWu <- N2")
						logger.NgapLog.Debugf("wrote %d bytes", n)
					}
				} else {
					ue.TemporaryCachedNASMessage = nasEnv
				}
			}
		default:
			logger.NgapLog.Errorf("unknown UE type: %T", ue)
		}
	}
}

func HandlePDUSessionResourceSetupRequest(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Setup Request")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var amfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var nasPDU *ngapType.NASPDU
	var pduSessionResourceSetupListSUReq *ngapType.PDUSessionResourceSetupListSUReq
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var pduSessionEstablishmentAccept *ngapType.NASPDU
	var ranUe context.RanUe
	var ranUeCtx *context.RanUeSharedCtx

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	pduSessionResourceSetupRequest := initiatingMessage.Value.PDUSessionResourceSetupRequest
	if pduSessionResourceSetupRequest == nil {
		logger.NgapLog.Errorln("PDUSessionResourceSetupRequest is nil")
		return
	}

	for _, ie := range pduSessionResourceSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			amfUeNgapID = ie.Value.AMFUENGAPID
			if amfUeNgapID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			ranUeNgapID = ie.Value.RANUENGAPID
			if ranUeNgapID == nil {
				logger.NgapLog.Errorln("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDNASPDU:
			logger.NgapLog.Debugln("decode IE NASPDU")
			nasPDU = ie.Value.NASPDU
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceSetupRequestList")
			pduSessionResourceSetupListSUReq = ie.Value.PDUSessionResourceSetupListSUReq
			if pduSessionResourceSetupListSUReq == nil {
				logger.NgapLog.Errorln("PDUSessionResourceSetupRequestList is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		// TODO: Send error indication to AMF
		logger.NgapLog.Errorln("sending error indication to AMF")
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if nasPDU != nil {
		n3iwfUe, ok := ranUe.(*context.N3IWFRanUe)
		if !ok {
			logger.NgapLog.Errorln("type assertion: RanUe -> N3iwfRanUe failed")
			return
		}
		if n3iwfUe.TCPConnection == nil {
			logger.NgapLog.Error("no IPSec NAS signalling SA for this UE")
			return
		}

		// Using a "NAS message envelope" to transport a NAS message
		// over the non-3GPP access between the UE and the N3IWF
		nasEnv := encapNasMsgToEnvelope(nasPDU)
		n, err := n3iwfUe.TCPConnection.Write(nasEnv)
		if err != nil {
			logger.NgapLog.Errorf("send NAS to UE failed: %+v", err)
			return
		}
		logger.NgapLog.Debugf("wrote %d bytes", n)
	}

	tempPDUSessionSetupData := ranUeCtx.TemporaryPDUSessionSetupData
	tempPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup

	if pduSessionResourceSetupListSUReq != nil {
		setupListSURes := new(ngapType.PDUSessionResourceSetupListSURes)
		failedListSURes := new(ngapType.PDUSessionResourceFailedToSetupListSURes)
		tempPDUSessionSetupData.SetupListSURes = setupListSURes
		tempPDUSessionSetupData.FailedListSURes = failedListSURes
		tempPDUSessionSetupData.Index = 0
		tempPDUSessionSetupData.UnactivatedPDUSession = nil
		tempPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup

		for _, item := range pduSessionResourceSetupListSUReq.List {
			pduSessionID := item.PDUSessionID.Value
			pduSessionEstablishmentAccept = item.PDUSessionNASPDU
			snssai := item.SNSSAI

			transfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
			err := aper.UnmarshalWithParams(item.PDUSessionResourceSetupRequestTransfer, &transfer, "valueExt")
			if err != nil {
				logger.NgapLog.Errorf("[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %+v",
					pduSessionID, err)
			}

			pduSession, err := ranUeCtx.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := message.BuildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				tempPDUSessionSetupData.UnactivatedPDUSession = append(tempPDUSessionSetupData.UnactivatedPDUSession, pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUeCtx.PduSessionList, pduSessionID)
				message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, resTransfer)
			}
		}
	}

	if tempPDUSessionSetupData != nil && len(tempPDUSessionSetupData.UnactivatedPDUSession) != 0 {
		switch ue := ranUe.(type) {
		case *context.N3IWFRanUe:
			spi, ok := n3iwfCtx.IkeSpiLoad(ue.RanUeNgapId)
			if !ok {
				logger.NgapLog.Errorf("cannot get SPI from ranNgapID: %+v", ranUeNgapID)
				return
			}
			n3iwfCtx.IkeServer.RcvEventCh <- context.NewCreatePDUSessionEvt(spi, len(ue.PduSessionList), ue.TemporaryPDUSessionSetupData)

			// TS 23.501 4.12.5 Requested PDU Session Establishment via Untrusted non-3GPP Access
			// After all IPsec Child SAs are established, the N3IWF shall forward to UE via the signalling IPsec SA
			// the PDU Session Establishment Accept message
			nasEnv := encapNasMsgToEnvelope(pduSessionEstablishmentAccept)

			// Cache the pduSessionEstablishmentAccept and forward to the UE after all CREATE_CHILD_SAs finish
			ue.TemporaryCachedNASMessage = nasEnv
		}
	}
}

func HandlePDUSessionResourceModifyRequest(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Modify Request")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var amfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var pduSessionResourceModifyListModReq *ngapType.PDUSessionResourceModifyListModReq
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	var ranUe context.RanUe
	var ranUeCtx *context.RanUeSharedCtx

	n3iwfCtx := context.N3IWFSelf()

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	pduSessionResourceModifyRequest := initiatingMessage.Value.PDUSessionResourceModifyRequest
	if pduSessionResourceModifyRequest == nil {
		logger.NgapLog.Errorln("PDUSessionResourceModifyRequest is nil")
		return
	}

	for _, ie := range pduSessionResourceModifyRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			amfUeNgapID = ie.Value.AMFUENGAPID
			if amfUeNgapID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			ranUeNgapID = ie.Value.RANUENGAPID
			if ranUeNgapID == nil {
				logger.NgapLog.Errorln("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceModifyListModReq")
			pduSessionResourceModifyListModReq = ie.Value.PDUSessionResourceModifyListModReq
			if pduSessionResourceModifyListModReq == nil {
				logger.NgapLog.Errorln("PDUSessionResourceModifyListModReq is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		message.SendPDUSessionResourceModifyResponse(nil, nil, nil, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and send error indication
			// Cause: Unknown local UE NGAP ID
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
		if ranUeCtx.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and send error indication
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	responseList := new(ngapType.PDUSessionResourceModifyListModRes)
	failedListModRes := new(ngapType.PDUSessionResourceFailedToModifyListModRes)
	if pduSessionResourceModifyListModReq != nil {
		var pduSession *context.PDUSession
		for _, item := range pduSessionResourceModifyListModReq.List {
			pduSessionID := item.PDUSessionID.Value
			// TODO: send NAS to UE
			// pduSessionNasPdu := item.NASPDU
			transfer := ngapType.PDUSessionResourceModifyRequestTransfer{}
			err := aper.UnmarshalWithParams(item.PDUSessionResourceModifyRequestTransfer, transfer, "valueExt")
			if err != nil {
				logger.NgapLog.Errorf(
					"[PDUSessionID: %d] PDUSessionResourceModifyRequestTransfer Decode Error: %+v", pduSessionID, err)
			}

			if pduSession = ranUeCtx.FindPDUSession(pduSessionID); pduSession == nil {
				logger.NgapLog.Errorf("[PDUSessionID: %d] Unknown PDU session ID", pduSessionID)

				cause := message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
				unsuccessfulTransfer, buildErr := message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceModifyUnsuccessfulTransfer Error: %+v", buildErr)
				}
				message.AppendPDUSessionResourceFailedToModifyListModRes(failedListModRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceModifyRequestTransfer(pduSession, transfer)
			if success {
				message.AppendPDUSessionResourceModifyListModRes(responseList, pduSessionID, resTransfer)
			} else {
				message.AppendPDUSessionResourceFailedToModifyListModRes(failedListModRes, pduSessionID, resTransfer)
			}
		}
	}

	message.SendPDUSessionResourceModifyResponse(ranUe, responseList, failedListModRes, nil)
}

func handlePDUSessionResourceModifyRequestTransfer(
	pduSession *context.PDUSession, transfer ngapType.PDUSessionResourceModifyRequestTransfer) (
	success bool, responseTransfer []byte,
) {
	logger.NgapLog.Debugln("handle PDU Session Resource Modify Request Transfer")

	var pduSessionAMBR *ngapType.PDUSessionAggregateMaximumBitRate
	var ulNGUUPTNLModifyList *ngapType.ULNGUUPTNLModifyList
	var networkInstance *ngapType.NetworkInstance
	var qosFlowAddOrModifyRequestList *ngapType.QosFlowAddOrModifyRequestList
	var qosFlowToReleaseList *ngapType.QosFlowListWithCause
	// var additionalULNGUUPTNLInformation *ngapType.UPTransportLayerInformation

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	// used for building response transfer
	var resDLNGUUPTNLInfo *ngapType.UPTransportLayerInformation
	var resULNGUUPTNLInfo *ngapType.UPTransportLayerInformation
	var resQosFlowAddOrModifyRequestList ngapType.QosFlowAddOrModifyResponseList
	var resQosFlowFailedToAddOrModifyList ngapType.QosFlowListWithCause

	for _, ie := range transfer.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate:
			logger.NgapLog.Debugln("decode IE PDUSessionAggregateMaximumBitRate")
			pduSessionAMBR = ie.Value.PDUSessionAggregateMaximumBitRate
		case ngapType.ProtocolIEIDULNGUUPTNLModifyList:
			logger.NgapLog.Debugln("decode IE ULNGUUPTNLModifyList")
			ulNGUUPTNLModifyList = ie.Value.ULNGUUPTNLModifyList
			if ulNGUUPTNLModifyList != nil && len(ulNGUUPTNLModifyList.List) == 0 {
				logger.NgapLog.Errorln("ULNGUUPTNLModifyList should have at least one element")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDNetworkInstance:
			logger.NgapLog.Debugln("decode IE NetworkInstance")
			networkInstance = ie.Value.NetworkInstance
		case ngapType.ProtocolIEIDQosFlowAddOrModifyRequestList:
			logger.NgapLog.Debugln("decode IE QosFLowAddOrModifyRequestList")
			qosFlowAddOrModifyRequestList = ie.Value.QosFlowAddOrModifyRequestList
			if qosFlowAddOrModifyRequestList != nil && len(qosFlowAddOrModifyRequestList.List) == 0 {
				logger.NgapLog.Errorln("QosFlowAddOrModifyRequestList should have at least one element")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDQosFlowToReleaseList:
			logger.NgapLog.Debugln("decode IE QosFlowToReleaseList")
			qosFlowToReleaseList = ie.Value.QosFlowToReleaseList
			if qosFlowToReleaseList != nil && len(qosFlowToReleaseList.List) == 0 {
				logger.NgapLog.Errorln("qosFlowToReleaseList should have at least one element")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDAdditionalULNGUUPTNLInformation:
			logger.NgapLog.Debugln("decode IE AdditionalULNGUUPTNLInformation")
			// additionalULNGUUPTNLInformation = ie.Value.AdditionalULNGUUPTNLInformation
		}
	}

	if len(iesCriticalityDiagnostics.List) != 0 {
		// build unsuccessful transfer
		cause := message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		unsuccessfulTransfer, err := message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, &criticalityDiagnostics)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceModifyUnsuccessfulTransfer Error: %+v", err)
		}

		responseTransfer = unsuccessfulTransfer
		return success, responseTransfer
	}

	if ulNGUUPTNLModifyList != nil {
		updateItem := ulNGUUPTNLModifyList.List[0]

		// TODO: update GTP tunnel

		logger.NgapLog.Infoln("update uplink NG-U user plane tunnel information")

		resULNGUUPTNLInfo = &updateItem.ULNGUUPTNLInformation
		resDLNGUUPTNLInfo = &updateItem.DLNGUUPTNLInformation
	}

	if qosFlowAddOrModifyRequestList != nil {
		for _, updateItem := range qosFlowAddOrModifyRequestList.List {
			target, ok := pduSession.QosFlows[updateItem.QosFlowIdentifier.Value]
			if ok {
				logger.NgapLog.Debugln("update qos flow level qos parameters")

				target.Parameters = *updateItem.QosFlowLevelQosParameters

				item := ngapType.QosFlowAddOrModifyResponseItem{
					QosFlowIdentifier: updateItem.QosFlowIdentifier,
				}

				resQosFlowAddOrModifyRequestList.List = append(resQosFlowAddOrModifyRequestList.List, item)
			} else {
				logger.NgapLog.Errorf("requested Qos flow not found, QosFlowID: %d", updateItem.QosFlowIdentifier)

				cause := message.BuildCause(
					ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnkownQosFlowID)

				item := ngapType.QosFlowWithCauseItem{
					QosFlowIdentifier: updateItem.QosFlowIdentifier,
					Cause:             *cause,
				}

				resQosFlowFailedToAddOrModifyList.List = append(resQosFlowFailedToAddOrModifyList.List, item)
			}
		}
	}

	if pduSessionAMBR != nil {
		logger.NgapLog.Debugln("store PDU session AMBR")
		pduSession.Ambr = pduSessionAMBR
	}

	if networkInstance != nil {
		// Used to select transport layer resource
		logger.NgapLog.Debugln("store network instance")
		pduSession.NetworkInstance = networkInstance
	}

	if qosFlowToReleaseList != nil {
		for _, releaseItem := range qosFlowToReleaseList.List {
			_, ok := pduSession.QosFlows[releaseItem.QosFlowIdentifier.Value]
			if ok {
				logger.NgapLog.Debugf("delete QosFlow. ID: %d", releaseItem.QosFlowIdentifier.Value)
				printAndGetCause(&releaseItem.Cause)
				delete(pduSession.QosFlows, releaseItem.QosFlowIdentifier.Value)
			}
		}
	}

	// if additionalULNGUUPTNLInformation != nil {
	// TODO: forward AdditionalULNGUUPTNLInfomation to S-NG-RAN
	// }

	encodeData, err := message.BuildPDUSessionResourceModifyResponseTransfer(
		resULNGUUPTNLInfo, resDLNGUUPTNLInfo, &resQosFlowAddOrModifyRequestList, &resQosFlowFailedToAddOrModifyList)
	if err != nil {
		logger.NgapLog.Errorf("build PDUSessionResourceModifyTransfer Error: %+v", err)
	}

	success = true
	responseTransfer = encodeData

	return success, responseTransfer
}

func HandlePDUSessionResourceModifyConfirm(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Modify Confirm")

	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var pDUSessionResourceModifyListModCfm *ngapType.PDUSessionResourceModifyListModCfm
	var pDUSessionResourceFailedToModifyListModCfm *ngapType.PDUSessionResourceFailedToModifyListModCfm
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics
	var ranUe context.RanUe
	var ranUeCtx *context.RanUeSharedCtx

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := pdu.SuccessfulOutcome
	if successfulOutcome == nil {
		logger.NgapLog.Errorln("successful Outcome is nil")
		return
	}

	pDUSessionResourceModifyConfirm := successfulOutcome.Value.PDUSessionResourceModifyConfirm
	if pDUSessionResourceModifyConfirm == nil {
		logger.NgapLog.Errorln("pDUSessionResourceModifyConfirm is nil")
		return
	}

	for _, ie := range pDUSessionResourceModifyConfirm.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			aMFUENGAPID = ie.Value.AMFUENGAPID
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			rANUENGAPID = ie.Value.RANUENGAPID
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModCfm:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceModifyListModCfm")
			pDUSessionResourceModifyListModCfm = ie.Value.PDUSessionResourceModifyListModCfm
		case ngapType.ProtocolIEIDPDUSessionResourceFailedToModifyListModCfm:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceFailedToModifyListModCfm")
			pDUSessionResourceFailedToModifyListModCfm = ie.Value.PDUSessionResourceFailedToModifyListModCfm
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	n3iwfCtx := context.N3IWFSelf()

	if rANUENGAPID != nil {
		var ok bool
		ranUe, ok = n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
			return
		}
		ranUeCtx = ranUe.GetSharedCtx()
	}

	if aMFUENGAPID != nil {
		if ranUe != nil {
			if ranUeCtx.AmfUeNgapId != aMFUENGAPID.Value {
				logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
					aMFUENGAPID.Value, ranUeCtx.AmfUeNgapId)
				return
			}
		} else {
			ranUe = amf.FindUeByAmfUeNgapID(aMFUENGAPID.Value)
			if ranUe == nil {
				logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d", aMFUENGAPID.Value)
				return
			}
		}
	}

	if ranUe == nil {
		logger.NgapLog.Warnln("RANUENGAPID and AMFUENGAPID are both nil")
		return
	}

	if pDUSessionResourceModifyListModCfm != nil {
		for _, item := range pDUSessionResourceModifyListModCfm.List {
			pduSessionId := item.PDUSessionID.Value
			logger.NgapLog.Debugf("PDU Session Id[%d] in Pdu Session Resource Modification Confrim List", pduSessionId)
			sess, exist := ranUeCtx.PduSessionList[pduSessionId]
			if !exist {
				logger.NgapLog.Warnf("PDU Session Id[%d] is not exist in Ue[ranUeNgapId:%d]", pduSessionId, ranUeCtx.RanUeNgapId)
			} else {
				transfer := ngapType.PDUSessionResourceModifyConfirmTransfer{}
				err := aper.UnmarshalWithParams(item.PDUSessionResourceModifyConfirmTransfer, &transfer, "valueExt")
				if err != nil {
					logger.NgapLog.Warnf("[PDUSessionID: %d] PDUSessionResourceSetupRequestTransfer Decode Error: %+v",
						pduSessionId, err)
				} else if transfer.QosFlowFailedToModifyList != nil {
					for _, flow := range transfer.QosFlowFailedToModifyList.List {
						logger.NgapLog.Warnf("delete QFI[%d] due to Qos Flow Failure in Pdu Session Resource Modification Confrim List",
							flow.QosFlowIdentifier.Value)
						delete(sess.QosFlows, flow.QosFlowIdentifier.Value)
					}
				}
			}
		}
	}
	if pDUSessionResourceFailedToModifyListModCfm != nil {
		for _, item := range pDUSessionResourceFailedToModifyListModCfm.List {
			pduSessionId := item.PDUSessionID.Value
			transfer := ngapType.PDUSessionResourceModifyIndicationUnsuccessfulTransfer{}
			err := aper.UnmarshalWithParams(item.PDUSessionResourceModifyIndicationUnsuccessfulTransfer, &transfer, "valueExt")
			if err != nil {
				logger.NgapLog.Warnf("[PDUSessionID: %d] PDUSessionResourceModifyIndicationUnsuccessfulTransfer Decode Error: %+v",
					pduSessionId, err)
			} else {
				printAndGetCause(&transfer.Cause)
			}
			logger.NgapLog.Debugf("release PDU Session Id[%d] due to PDU Session Resource Modify Indication Unsuccessful", pduSessionId)
			delete(ranUeCtx.PduSessionList, pduSessionId)
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
}

func HandlePDUSessionResourceReleaseCommand(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Release Command")
	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	// var rANPagingPriority *ngapType.RANPagingPriority
	// var nASPDU *ngapType.NASPDU
	var pDUSessionResourceToReleaseListRelCmd *ngapType.PDUSessionResourceToReleaseListRelCmd

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating Message is nil")
		return
	}

	pDUSessionResourceReleaseCommand := initiatingMessage.Value.PDUSessionResourceReleaseCommand
	if pDUSessionResourceReleaseCommand == nil {
		logger.NgapLog.Errorln("pDUSessionResourceReleaseCommand is nil")
		return
	}

	for _, ie := range pDUSessionResourceReleaseCommand.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			aMFUENGAPID = ie.Value.AMFUENGAPID
			if aMFUENGAPID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			rANUENGAPID = ie.Value.RANUENGAPID
			if rANUENGAPID == nil {
				logger.NgapLog.Errorln("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANPagingPriority:
			logger.NgapLog.Debugln("decode IE RANPagingPriority")
			// rANPagingPriority = ie.Value.RANPagingPriority
		case ngapType.ProtocolIEIDNASPDU:
			logger.NgapLog.Debugln("decode IE NASPDU")
			// nASPDU = ie.Value.NASPDU
		case ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd:
			logger.NgapLog.Debugln("decode IE PDUSessionResourceToReleaseListRelCmd")
			pDUSessionResourceToReleaseListRelCmd = ie.Value.PDUSessionResourceToReleaseListRelCmd
			if pDUSessionResourceToReleaseListRelCmd == nil {
				logger.NgapLog.Errorln("PDUSessionResourceToReleaseListRelCmd is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapType.ProcedureCodePDUSessionResourceRelease
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}
	ranUeCtx := ranUe.GetSharedCtx()

	if ranUeCtx.AmfUeNgapId != aMFUENGAPID.Value {
		logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
			aMFUENGAPID.Value, ranUeCtx.AmfUeNgapId)
		cause := message.BuildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID)
		message.SendErrorIndication(amf, nil, &rANUENGAPID.Value, cause, nil)
		return
	}

	// if rANPagingPriority != nil {
	// n3iwf does not support paging
	// }

	releaseList := ngapType.PDUSessionResourceReleasedListRelRes{}
	var releaseIdList []int64
	for _, item := range pDUSessionResourceToReleaseListRelCmd.List {
		pduSessionId := item.PDUSessionID.Value
		transfer := ngapType.PDUSessionResourceReleaseCommandTransfer{}
		err := aper.UnmarshalWithParams(item.PDUSessionResourceReleaseCommandTransfer, &transfer, "valueExt")
		if err != nil {
			logger.NgapLog.Warnf("[PDUSessionID: %d] PDUSessionResourceReleaseCommandTransfer Decode Error: %+v", pduSessionId, err)
		} else {
			printAndGetCause(&transfer.Cause)
		}
		logger.NgapLog.Debugf("release PDU Session Id[%d] due to PDU Session Resource Release Command", pduSessionId)
		delete(ranUeCtx.PduSessionList, pduSessionId)

		// response list
		releaseItem := ngapType.PDUSessionResourceReleasedItemRelRes{
			PDUSessionID: item.PDUSessionID,
			PDUSessionResourceReleaseResponseTransfer: getPDUSessionResourceReleaseResponseTransfer(),
		}
		releaseList.List = append(releaseList.List, releaseItem)

		releaseIdList = append(releaseIdList, pduSessionId)
	}

	localSPI, ok := n3iwfCtx.IkeSpiLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("cannot get SPI from RanUeNgapID: %+v", rANUENGAPID.Value)
		return
	}
	ranUe.GetSharedCtx().PduSessResRelState = context.PduSessResRelStateOngoing

	n3iwfCtx.IkeServer.RcvEventCh <- context.NewSendChildSADeleteRequestEvt(localSPI, releaseIdList)

	ranUeCtx.PduSessionReleaseList = releaseList
	// if nASPDU != nil {
	// TODO: Send NAS to UE
	// }
}

func HandleErrorIndication(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Error Indication")

	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var cause *ngapType.Cause
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}
	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}
	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("InitiatingMessage is nil")
		return
	}
	errorIndication := initiatingMessage.Value.ErrorIndication
	if errorIndication == nil {
		logger.NgapLog.Errorln("ErrorIndication is nil")
		return
	}

	for _, ie := range errorIndication.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			aMFUENGAPID = ie.Value.AMFUENGAPID
			logger.NgapLog.Debugln("decode IE AmfUeNgapID")
		case ngapType.ProtocolIEIDRANUENGAPID:
			rANUENGAPID = ie.Value.RANUENGAPID
			logger.NgapLog.Debugln("decode IE RanUeNgapID")
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause
			logger.NgapLog.Debugln("decode IE Cause")
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
		}
	}

	if cause == nil && criticalityDiagnostics == nil {
		logger.NgapLog.Errorln("both Cause IE and CriticalityDiagnostics IE are nil, should have at least one")
		return
	}

	if (aMFUENGAPID == nil) != (rANUENGAPID == nil) {
		logger.NgapLog.Errorln("one of UE NGAP ID is not included in this message")
		return
	}

	if (aMFUENGAPID != nil) && (rANUENGAPID != nil) {
		logger.NgapLog.Debugln("UE-associated procedure error")
		logger.NgapLog.Warnf("AMF UE NGAP ID is defined, value = %d", aMFUENGAPID.Value)
		logger.NgapLog.Warnf("RAN UE NGAP ID is defined, value = %d", rANUENGAPID.Value)
	}

	printAndGetCause(cause)

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if ok {
		err := releaseIkeUeAndRanUe(ranUe)
		if err != nil {
			logger.NgapLog.Warnf("handle error indication: %v", err)
		}
	}

	ranUe = amf.FindUeByAmfUeNgapID(aMFUENGAPID.Value)
	if ranUe != nil {
		err := releaseIkeUeAndRanUe(ranUe)
		if err != nil {
			logger.NgapLog.Warnf("handle error indication: %v", err)
		}
	}

	// TODO: handle error based on cause/criticalityDiagnostics
}

func HandleUERadioCapabilityCheckRequest(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE Radio Capability Check Request")
	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var uERadioCapability *ngapType.UERadioCapability
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("InitiatingMessage is nil")
		return
	}

	uERadioCapabilityCheckRequest := initiatingMessage.Value.UERadioCapabilityCheckRequest
	if uERadioCapabilityCheckRequest == nil {
		logger.NgapLog.Errorln("uERadioCapabilityCheckRequest is nil")
		return
	}

	for _, ie := range uERadioCapabilityCheckRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			logger.NgapLog.Debugln("decode IE AMFUENGAPID")
			aMFUENGAPID = ie.Value.AMFUENGAPID
			if aMFUENGAPID == nil {
				logger.NgapLog.Errorln("AMFUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			logger.NgapLog.Debugln("decode IE RANUENGAPID")
			rANUENGAPID = ie.Value.RANUENGAPID
			if rANUENGAPID == nil {
				logger.NgapLog.Errorln("RANUENGAPID is nil")
				item := buildCriticalityDiagnosticsIEItem(
					ngapType.CriticalityPresentReject, ie.Id.Value, ngapType.TypeOfErrorPresentMissing)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
			}
		case ngapType.ProtocolIEIDUERadioCapability:
			logger.NgapLog.Debugln("decode IE UERadioCapability")
			uERadioCapability = ie.Value.UERadioCapability
		}
	}

	if len(iesCriticalityDiagnostics.List) > 0 {
		procudureCode := ngapType.ProcedureCodeUERadioCapabilityCheck
		trigger := ngapType.TriggeringMessagePresentInitiatingMessage
		criticality := ngapType.CriticalityPresentReject
		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procudureCode, &trigger, &criticality, &iesCriticalityDiagnostics)
		message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	ranUe.GetSharedCtx().RadioCapability = uERadioCapability
}

func HandleAMFConfigurationUpdate(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle AMF Configuration Updaet")

	var aMFName *ngapType.AMFName
	var servedGUAMIList *ngapType.ServedGUAMIList
	var relativeAMFCapacity *ngapType.RelativeAMFCapacity
	var pLMNSupportList *ngapType.PLMNSupportList
	var aMFTNLAssociationToAddList *ngapType.AMFTNLAssociationToAddList
	var aMFTNLAssociationToRemoveList *ngapType.AMFTNLAssociationToRemoveList
	var aMFTNLAssociationToUpdateList *ngapType.AMFTNLAssociationToUpdateList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("InitiatingMessage is nil")
		return
	}

	aMFConfigurationUpdate := initiatingMessage.Value.AMFConfigurationUpdate
	if aMFConfigurationUpdate == nil {
		logger.NgapLog.Errorln("aMFConfigurationUpdate is nil")
		return
	}

	for _, ie := range aMFConfigurationUpdate.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			logger.NgapLog.Debugln("decode IE AMFName")
			aMFName = ie.Value.AMFName
		case ngapType.ProtocolIEIDServedGUAMIList:
			logger.NgapLog.Debugln("decode IE ServedGUAMIList")
			servedGUAMIList = ie.Value.ServedGUAMIList
		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			logger.NgapLog.Debugln("decode IE RelativeAMFCapacity")
			relativeAMFCapacity = ie.Value.RelativeAMFCapacity
		case ngapType.ProtocolIEIDPLMNSupportList:
			logger.NgapLog.Debugln("decode IE PLMNSupportList")
			pLMNSupportList = ie.Value.PLMNSupportList
		case ngapType.ProtocolIEIDAMFTNLAssociationToAddList:
			logger.NgapLog.Debugln("decode IE AMFTNLAssociationToAddList")
			aMFTNLAssociationToAddList = ie.Value.AMFTNLAssociationToAddList
		case ngapType.ProtocolIEIDAMFTNLAssociationToRemoveList:
			logger.NgapLog.Debugln("decode IE AMFTNLAssociationToRemoveList")
			aMFTNLAssociationToRemoveList = ie.Value.AMFTNLAssociationToRemoveList
		case ngapType.ProtocolIEIDAMFTNLAssociationToUpdateList:
			logger.NgapLog.Debugln("decode IE AMFTNLAssociationToUpdateList")
			aMFTNLAssociationToUpdateList = ie.Value.AMFTNLAssociationToUpdateList
		}
	}

	if aMFName != nil {
		amf.AMFName = aMFName
	}
	if servedGUAMIList != nil {
		amf.ServedGUAMIList = servedGUAMIList
	}

	if relativeAMFCapacity != nil {
		amf.RelativeAMFCapacity = relativeAMFCapacity
	}

	if pLMNSupportList != nil {
		amf.PLMNSupportList = pLMNSupportList
	}

	successList := []ngapType.AMFTNLAssociationSetupItem{}
	if aMFTNLAssociationToAddList != nil {
		// TODO: Establish TNL Association with AMF
		for _, item := range aMFTNLAssociationToAddList.List {
			tnlItem := amf.AddAMFTNLAssociationItem(item.AMFTNLAssociationAddress)
			tnlItem.TNLAddressWeightFactor = &item.TNLAddressWeightFactor.Value
			if item.TNLAssociationUsage != nil {
				tnlItem.TNLAssociationUsage = item.TNLAssociationUsage
			}
			setupItem := ngapType.AMFTNLAssociationSetupItem{
				AMFTNLAssociationAddress: item.AMFTNLAssociationAddress,
			}
			successList = append(successList, setupItem)
		}
	}
	if aMFTNLAssociationToRemoveList != nil {
		// TODO: Remove TNL Association with AMF
		for _, item := range aMFTNLAssociationToRemoveList.List {
			amf.DeleteAMFTNLAssociationItem(item.AMFTNLAssociationAddress)
		}
	}
	if aMFTNLAssociationToUpdateList != nil {
		// TODO: Update TNL Association with AMF
		for _, item := range aMFTNLAssociationToUpdateList.List {
			tnlItem := amf.FindAMFTNLAssociationItem(item.AMFTNLAssociationAddress)
			if tnlItem == nil {
				continue
			}
			if item.TNLAddressWeightFactor != nil {
				tnlItem.TNLAddressWeightFactor = &item.TNLAddressWeightFactor.Value
			}
			if item.TNLAssociationUsage != nil {
				tnlItem.TNLAssociationUsage = item.TNLAssociationUsage
			}
		}
	}

	var setupList *ngapType.AMFTNLAssociationSetupList
	if len(successList) > 0 {
		setupList = &ngapType.AMFTNLAssociationSetupList{
			List: successList,
		}
	}
	message.SendAMFConfigurationUpdateAcknowledge(amf, setupList, nil, nil)
}

func HandleRANConfigurationUpdateAcknowledge(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle RAN Configuration Update Acknowledge")

	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := pdu.SuccessfulOutcome
	if successfulOutcome == nil {
		logger.NgapLog.Errorln("SuccessfulOutcome is nil")
		return
	}

	rANConfigurationUpdateAcknowledge := successfulOutcome.Value.RANConfigurationUpdateAcknowledge
	if rANConfigurationUpdateAcknowledge == nil {
		logger.NgapLog.Errorln("rANConfigurationUpdateAcknowledge is nil")
		return
	}

	for _, ie := range rANConfigurationUpdateAcknowledge.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
}

func HandleRANConfigurationUpdateFailure(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle RAN Configuration Update Failure")

	var cause *ngapType.Cause
	var timeToWait *ngapType.TimeToWait
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	n3iwfCtx := context.N3IWFSelf()

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	if unsuccessfulOutcome == nil {
		logger.NgapLog.Errorln("unsuccessfulOutcome is nil")
		return
	}

	rANConfigurationUpdateFailure := unsuccessfulOutcome.Value.RANConfigurationUpdateFailure
	if rANConfigurationUpdateFailure == nil {
		logger.NgapLog.Errorln("rANConfigurationUpdateFailure is nil")
		return
	}

	for _, ie := range rANConfigurationUpdateFailure.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			logger.NgapLog.Debugln("decode IE Cause")
			cause = ie.Value.Cause
		case ngapType.ProtocolIEIDTimeToWait:
			logger.NgapLog.Debugln("decode IE TimeToWait")
			timeToWait = ie.Value.TimeToWait
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			logger.NgapLog.Debugln("decode IE CriticalityDiagnostics")
			criticalityDiagnostics = ie.Value.CriticalityDiagnostics
		}
	}

	printAndGetCause(cause)

	printCriticalityDiagnostics(criticalityDiagnostics)

	var waitingTime int

	if timeToWait != nil {
		switch timeToWait.Value {
		case ngapType.TimeToWaitPresentV1s:
			waitingTime = 1
		case ngapType.TimeToWaitPresentV2s:
			waitingTime = 2
		case ngapType.TimeToWaitPresentV5s:
			waitingTime = 5
		case ngapType.TimeToWaitPresentV10s:
			waitingTime = 10
		case ngapType.TimeToWaitPresentV20s:
			waitingTime = 20
		case ngapType.TimeToWaitPresentV60s:
			waitingTime = 60
		}
	}

	if waitingTime != 0 {
		logger.NgapLog.Infof("wait at lease %ds to resend RAN Configuration Update to same AMF[%s]",
			waitingTime, amf.SCTPAddr)
		n3iwfCtx.AMFReInitAvailableListStore(amf.SCTPAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			logger.NgapLog.Infoln("re-send Ran Configuration Update Message when waiting time expired")
			n3iwfCtx.AMFReInitAvailableListStore(amf.SCTPAddr, true)
			message.SendRANConfigurationUpdate(n3iwfCtx, amf)
		})
		return
	}
	message.SendRANConfigurationUpdate(n3iwfCtx, amf)
}

func HandleDownlinkRANConfigurationTransfer(pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Downlink RAN Configuration Transfer")
}

func HandleDownlinkRANStatusTransfer(pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Downlink RAN Status Transfer")
}

func HandleAMFStatusIndication(pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle AMF Status Indication")
}

func HandleLocationReportingControl(pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Location Reporting Control")
}

func HandleUETNLAReleaseRequest(pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE TNLA Release Request")
}

func HandleOverloadStart(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Overload Start")

	var aMFOverloadResponse *ngapType.OverloadResponse
	var aMFTrafficLoadReductionIndication *ngapType.TrafficLoadReductionIndication
	var overloadStartNSSAIList *ngapType.OverloadStartNSSAIList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if pdu == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("InitiatingMessage is nil")
		return
	}

	overloadStart := initiatingMessage.Value.OverloadStart
	if overloadStart == nil {
		logger.NgapLog.Errorln("overloadStart is nil")
		return
	}

	for _, ie := range overloadStart.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFOverloadResponse:
			logger.NgapLog.Debugln("decode IE AMFOverloadResponse")
			aMFOverloadResponse = ie.Value.AMFOverloadResponse
		case ngapType.ProtocolIEIDAMFTrafficLoadReductionIndication:
			logger.NgapLog.Debugln("decode IE AMFTrafficLoadReductionIndication")
			aMFTrafficLoadReductionIndication = ie.Value.AMFTrafficLoadReductionIndication
		case ngapType.ProtocolIEIDOverloadStartNSSAIList:
			logger.NgapLog.Debugln("decode IE OverloadStartNSSAIList")
			overloadStartNSSAIList = ie.Value.OverloadStartNSSAIList
		}
	}
	// TODO: restrict rule about overload action
	amf.StartOverload(aMFOverloadResponse, aMFTrafficLoadReductionIndication, overloadStartNSSAIList)
}

func HandleOverloadStop(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Overload Stop")

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}
	// TODO: remove restrict about overload action
	amf.StopOverload()
}

func buildCriticalityDiagnostics(
	procedureCode *int64,
	triggeringMessage *aper.Enumerated,
	procedureCriticality *aper.Enumerated,
	iesCriticalityDiagnostics *ngapType.CriticalityDiagnosticsIEList) (
	criticalityDiagnostics ngapType.CriticalityDiagnostics,
) {
	if procedureCode != nil {
		criticalityDiagnostics.ProcedureCode = new(ngapType.ProcedureCode)
		criticalityDiagnostics.ProcedureCode.Value = *procedureCode
	}

	if triggeringMessage != nil {
		criticalityDiagnostics.TriggeringMessage = new(ngapType.TriggeringMessage)
		criticalityDiagnostics.TriggeringMessage.Value = *triggeringMessage
	}

	if procedureCriticality != nil {
		criticalityDiagnostics.ProcedureCriticality = new(ngapType.Criticality)
		criticalityDiagnostics.ProcedureCriticality.Value = *procedureCriticality
	}

	if iesCriticalityDiagnostics != nil {
		criticalityDiagnostics.IEsCriticalityDiagnostics = iesCriticalityDiagnostics
	}

	return criticalityDiagnostics
}

func buildCriticalityDiagnosticsIEItem(ieCriticality aper.Enumerated, ieID int64, typeOfErr aper.Enumerated) (
	item ngapType.CriticalityDiagnosticsIEItem,
) {
	item = ngapType.CriticalityDiagnosticsIEItem{
		IECriticality: ngapType.Criticality{
			Value: ieCriticality,
		},
		IEID: ngapType.ProtocolIEID{
			Value: ieID,
		},
		TypeOfError: ngapType.TypeOfError{
			Value: typeOfErr,
		},
	}

	return item
}

func printAndGetCause(cause *ngapType.Cause) (present int, value aper.Enumerated) {
	if cause == nil {
		logger.NgapLog.Errorln("cause is nil")
		return
	}
	present = cause.Present
	switch present {
	case ngapType.CausePresentRadioNetwork:
		logger.NgapLog.Warnf("cause RadioNetwork[%d]", cause.RadioNetwork.Value)
		value = cause.RadioNetwork.Value
	case ngapType.CausePresentTransport:
		logger.NgapLog.Warnf("cause Transport[%d]", cause.Transport.Value)
		value = cause.Transport.Value
	case ngapType.CausePresentProtocol:
		logger.NgapLog.Warnf("cause Protocol[%d]", cause.Protocol.Value)
		value = cause.Protocol.Value
	case ngapType.CausePresentNas:
		logger.NgapLog.Warnf("cause Nas[%d]", cause.Nas.Value)
		value = cause.Nas.Value
	case ngapType.CausePresentMisc:
		logger.NgapLog.Warnf("cause Misc[%d]", cause.Misc.Value)
		value = cause.Misc.Value
	default:
		logger.NgapLog.Errorf("invalid Cause group[%d]", present)
	}
	return
}

func printCriticalityDiagnostics(criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	if criticalityDiagnostics == nil {
		logger.NgapLog.Warnln("input is nil")
		return
	}
	iesCriticalityDiagnostics := criticalityDiagnostics.IEsCriticalityDiagnostics
	if iesCriticalityDiagnostics == nil {
		logger.NgapLog.Warnln("IEsCriticalityDiagnostics is nil")
		return
	}
	for i, item := range iesCriticalityDiagnostics.List {
		logger.NgapLog.Warnf("criticality IE item %d: IE ID: %d", i+1, item.IEID.Value)
		switch item.IECriticality.Value {
		case ngapType.CriticalityPresentReject:
			logger.NgapLog.Warnln("IE Criticality: Reject")
		case ngapType.CriticalityPresentIgnore:
			logger.NgapLog.Warnln("IE Criticality: Ignore")
		case ngapType.CriticalityPresentNotify:
			logger.NgapLog.Warnln("IE Criticality: Notify")
		}
		switch item.TypeOfError.Value {
		case ngapType.TypeOfErrorPresentNotUnderstood:
			logger.NgapLog.Warnln("type of error: Not Understood")
		case ngapType.TypeOfErrorPresentMissing:
			logger.NgapLog.Warnln("type of error: Missing")
		}
	}
}

func getPDUSessionResourceReleaseResponseTransfer() []byte {
	data := ngapType.PDUSessionResourceReleaseResponseTransfer{}
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		logger.NgapLog.Errorf("aper MarshalWithParams error in getPDUSessionResourceReleaseResponseTransfer: %d", err)
	}
	return encodeData
}

func HandleEvent(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("NGAP event handle")

	switch ngapEvent.Type() {
	case context.UnmarshalEAP5GData:
		HandleUnmarshalEAP5GData(ngapEvent)
	case context.SendInitialUEMessage:
		HandleSendInitialUEMessage(ngapEvent)
	case context.SendPDUSessionResourceSetupResponse:
		HandleSendPDUSessionResourceSetupResponse(ngapEvent)
	case context.SendNASMsg:
		HandleSendNASMsg(ngapEvent)
	case context.StartTCPSignalNASMsg:
		HandleStartTCPSignalNASMsg(ngapEvent)
	case context.NASTCPConnEstablishedComplete:
		HandleNASTCPConnEstablishedComplete(ngapEvent)
	case context.SendUEContextRelease:
		HandleSendSendUEContextRelease(ngapEvent)
	case context.SendUEContextReleaseRequest:
		HandleSendUEContextReleaseRequest(ngapEvent)
	case context.SendUEContextReleaseComplete:
		HandleSendUEContextReleaseComplete(ngapEvent)
	case context.SendPDUSessionResourceRelease:
		HandleSendSendPDUSessionResourceRelease(ngapEvent)
	case context.SendPDUSessionResourceReleaseResponse:
		HandleSendPDUSessionResourceReleaseRes(ngapEvent)
	case context.GetNGAPContext:
		HandleGetNGAPContext(ngapEvent)
	case context.SendUplinkNASTransport:
		HandleSendUplinkNASTransport(ngapEvent)
	case context.SendInitialContextSetupResponse:
		HandleSendInitialContextSetupResponse(ngapEvent)
	default:
		logger.NgapLog.Errorf("undefined NGAP event type")
		return
	}
}

func HandleGetNGAPContext(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle HandleGetNGAPContext Event")

	evt := ngapEvent.(*context.GetNGAPContextEvt)
	ranUeNgapId := evt.RanUeNgapId
	ngapCxtReqNumlist := evt.NgapCxtReqNumlist

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	var ngapCxt []any

	for _, num := range ngapCxtReqNumlist {
		switch num {
		case context.CxtTempPDUSessionSetupData:
			ngapCxt = append(ngapCxt, ranUe.GetSharedCtx().TemporaryPDUSessionSetupData)
		default:
			logger.NgapLog.Errorf("receive undefined NGAP Context Request number: %d", num)
		}
	}

	spi, ok := n3iwfCtx.IkeSpiLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get spi from ngapid: %d", ranUeNgapId)
		return
	}

	n3iwfCtx.IkeServer.RcvEventCh <- context.NewGetNGAPContextRepEvt(spi, ngapCxtReqNumlist, ngapCxt)
}

func HandleUnmarshalEAP5GData(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle UnmarshalEAP5GData Event")

	evt := ngapEvent.(*context.UnmarshalEAP5GDataEvt)
	spi := evt.LocalSPI
	eapVendorData := evt.EAPVendorData
	isInitialUE := evt.IsInitialUE

	n3iwfCtx := context.N3IWFSelf()

	anParameters, nasPDU, err := message.UnmarshalEAP5GData(eapVendorData)
	if err != nil {
		logger.NgapLog.Errorf("unmarshalling EAP-5G packet failed: %+v", err)
		return
	}

	if !isInitialUE { // ikeSA.ikeUE == nil
		logger.NgapLog.Debugln("select AMF with the following AN parameters:")
		if anParameters.GUAMI == nil {
			logger.NgapLog.Debugln("\tGUAMI: nil")
		} else {
			logger.NgapLog.Debugf("\tGUAMI: PLMNIdentity[% x], "+
				"AMFRegionID[% x], AMFSetID[% x], AMFPointer[% x]",
				anParameters.GUAMI.PLMNIdentity, anParameters.GUAMI.AMFRegionID,
				anParameters.GUAMI.AMFSetID, anParameters.GUAMI.AMFPointer)
		}
		if anParameters.SelectedPLMNID == nil {
			logger.NgapLog.Debugln("\tSelectedPLMNID: nil")
		} else {
			logger.NgapLog.Debugf("\tSelectedPLMNID: % v", anParameters.SelectedPLMNID.Value)
		}
		if anParameters.RequestedNSSAI == nil {
			logger.NgapLog.Debugln("\tRequestedNSSAI: nil")
		} else {
			logger.NgapLog.Debugln("\tRequestedNSSAI:")
			for i := 0; i < len(anParameters.RequestedNSSAI.List); i++ {
				logger.NgapLog.Debugln("\tRequestedNSSAI:")
				logger.NgapLog.Debugf("\t\tSNSSAI %d:", i+1)
				logger.NgapLog.Debugf("\t\t\tSST: % x", anParameters.RequestedNSSAI.List[i].SNSSAI.SST.Value)
				sd := anParameters.RequestedNSSAI.List[i].SNSSAI.SD
				if sd == nil {
					logger.NgapLog.Debugln("\t\t\tSD: nil")
				} else {
					logger.NgapLog.Debugf("\t\t\tSD: % x", sd.Value)
				}
			}
		}

		selectedAMF := n3iwfCtx.AMFSelection(anParameters.GUAMI, anParameters.SelectedPLMNID)
		if selectedAMF == nil {
			n3iwfCtx.IkeServer.RcvEventCh <- context.NewSendEAP5GFailureMsgEvt(spi, context.ErrAMFSelection)
		} else {
			n3iwfUe := n3iwfCtx.NewN3iwfRanUe()
			n3iwfUe.AMF = selectedAMF
			if anParameters.EstablishmentCause != nil {
				value := uint64(anParameters.EstablishmentCause.Value)
				if value > uint64(math.MaxInt16) {
					logger.NgapLog.Errorf("anParameters.EstablishmentCause.Value exceeds int16: %+d", value)
					return
				}
				n3iwfUe.RRCEstablishmentCause = int16(value)
			}

			n3iwfCtx.IkeServer.RcvEventCh <- context.NewUnmarshalEAP5GDataResponseEvt(spi, n3iwfUe.RanUeNgapId, nasPDU)
		}
	} else {
		ranUeNgapId := evt.RanUeNgapId
		ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
		if !ok {
			logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
			return
		}
		message.SendUplinkNASTransport(ranUe, nasPDU)
	}
}

func HandleSendInitialUEMessage(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendInitialUEMessage Event")

	evt := ngapEvent.(*context.SendInitialUEMessageEvt)
	ranUeNgapId := evt.RanUeNgapId
	ipv4Addr := evt.IPv4Addr
	ipv4Port := evt.IPv4Port
	nasPDU := evt.NasPDU

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}
	ranUeCtx := ranUe.GetSharedCtx()
	ranUeCtx.IPAddrv4 = ipv4Addr
	ranUeCtx.PortNumber = int32(ipv4Port)
	message.SendInitialUEMessage(ranUeCtx.AMF, ranUe, nasPDU)
}

func HandleSendPDUSessionResourceSetupResponse(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendPDUSessionResourceSetupResponse Event")

	evt := ngapEvent.(*context.SendPDUSessionResourceSetupResEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	ranUeCtx := ranUe.GetSharedCtx()
	temporaryPDUSessionSetupData := ranUeCtx.TemporaryPDUSessionSetupData

	if len(temporaryPDUSessionSetupData.UnactivatedPDUSession) != 0 {
		for index, pduSession := range temporaryPDUSessionSetupData.UnactivatedPDUSession {
			errStr := temporaryPDUSessionSetupData.FailedErrStr[index]
			if errStr != context.ErrNil {
				var cause ngapType.Cause
				switch errStr {
				case context.ErrTransportResourceUnavailable:
					cause = ngapType.Cause{
						Present: ngapType.CausePresentTransport,
						Transport: &ngapType.CauseTransport{
							Value: ngapType.CauseTransportPresentTransportResourceUnavailable,
						},
					}
				default:
					logger.NgapLog.Errorf("undefined event error string: %+s", errStr.Error())
					return
				}

				transfer, err := message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDU Session Resource Setup Unsuccessful Transfer Failed: %+v", err)
					continue
				}

				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
					message.AppendPDUSessionResourceFailedToSetupListCxtRes(
						temporaryPDUSessionSetupData.FailedListCxtRes, pduSession.Id, transfer)
				} else {
					message.AppendPDUSessionResourceFailedToSetupListSURes(
						temporaryPDUSessionSetupData.FailedListSURes, pduSession.Id, transfer)
				}
			} else {
				var gtpAddr string
				switch ranUe.(type) {
				case *context.N3IWFRanUe:
					gtpAddr = n3iwfCtx.GtpBindAddress
				}

				// Append NGAP PDU session resource setup response transfer
				transfer, err := message.BuildPDUSessionResourceSetupResponseTransfer(pduSession, gtpAddr)
				if err != nil {
					logger.NgapLog.Errorf("build PDU session resource setup response transfer failed: %+v", err)
					return
				}
				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
					message.AppendPDUSessionResourceSetupListCxtRes(
						temporaryPDUSessionSetupData.SetupListCxtRes, pduSession.Id, transfer)
				} else {
					message.AppendPDUSessionResourceSetupListSURes(
						temporaryPDUSessionSetupData.SetupListSURes, pduSession.Id, transfer)
				}
			}
		}

		if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
			message.SendInitialContextSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListCxtRes,
				temporaryPDUSessionSetupData.FailedListCxtRes, nil)
		} else {
			message.SendPDUSessionResourceSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListSURes,
				temporaryPDUSessionSetupData.FailedListSURes, nil)
		}
	} else {
		message.SendInitialContextSetupResponse(ranUe, nil, nil, nil)
	}
}

func HandleSendNASMsg(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendNASMsg Event")

	evt := ngapEvent.(*context.SendNASMsgEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	n3iwfUe, ok := ranUe.(*context.N3IWFRanUe)
	if !ok {
		logger.NgapLog.Errorln("type assertion: RanUe -> N3iwfUe failed")
		return
	}

	if n, ikeErr := n3iwfUe.TCPConnection.Write(n3iwfUe.TemporaryCachedNASMessage); ikeErr != nil {
		logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", ikeErr)
	} else {
		logger.NgapLog.Debugf("forward PDU Seesion Establishment Accept to UE. Wrote %d bytes", n)
		n3iwfUe.TemporaryCachedNASMessage = nil
	}
}

func HandleStartTCPSignalNASMsg(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle StartTCPSignalNASMsg Event")

	evt := ngapEvent.(*context.StartTCPSignalNASMsgEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	n3iwfUe, ok := ranUe.(*context.N3IWFRanUe)
	if !ok {
		logger.NgapLog.Errorln("type assertion: RanUe -> N3iwfUe failed")
		return
	}

	n3iwfUe.IsNASTCPConnEstablished = true
}

func HandleNASTCPConnEstablishedComplete(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle NASTCPConnEstablishedComplete Event")

	evt := ngapEvent.(*context.NASTCPConnEstablishedCompleteEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}
	n3iwfUe, ok := ranUe.(*context.N3IWFRanUe)
	if !ok {
		logger.NgapLog.Errorln("type assertion: RanUe -> N3iwfUe failed")
		return
	}

	n3iwfUe.IsNASTCPConnEstablishedComplete = true

	if n3iwfUe.TemporaryCachedNASMessage != nil {
		// Send to UE
		if n, err := n3iwfUe.TCPConnection.Write(n3iwfUe.TemporaryCachedNASMessage); err != nil {
			logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", err)
		} else {
			logger.NgapLog.Debugln("forward NWu <- N2")
			logger.NgapLog.Debugf("wrote %d bytes", n)
		}
		n3iwfUe.TemporaryCachedNASMessage = nil
	}
}

func HandleSendUEContextReleaseRequest(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendUEContextReleaseRequest Event")

	evt := ngapEvent.(*context.SendUEContextReleaseRequestEvt)

	ranUeNgapId := evt.RanUeNgapId
	errMsg := evt.ErrMsg

	var cause *ngapType.Cause
	switch errMsg {
	case context.ErrRadioConnWithUeLost:
		cause = message.BuildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
	case context.ErrNil:
	default:
		logger.NgapLog.Errorf("undefined event error string: %+s", errMsg.Error())
		return
	}

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	message.SendUEContextReleaseRequest(ranUe, *cause)
}

func HandleSendUEContextReleaseComplete(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendUEContextReleaseComplete Event")

	evt := ngapEvent.(*context.SendUEContextReleaseCompleteEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	if err := ranUe.Remove(); err != nil {
		logger.NgapLog.Errorf("delete RanUe Context error: %+v", err)
	}
	message.SendUEContextReleaseComplete(ranUe, nil)
}

func HandleSendPDUSessionResourceReleaseRes(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendPDUSessionResourceReleaseResponse Event")

	evt := ngapEvent.(*context.SendPDUSessionResourceReleaseResEvt)
	ranUeNgapId := evt.RanUeNgapId

	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	message.SendPDUSessionResourceReleaseResponse(ranUe, ranUe.GetSharedCtx().PduSessionReleaseList, nil)
}

func HandleSendUplinkNASTransport(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendUplinkNASTransport Event")

	evt := ngapEvent.(*context.SendUplinkNASTransportEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	message.SendUplinkNASTransport(ranUe, evt.Pdu)
}

func HandleSendInitialContextSetupResponse(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendInitialContextSetupResponse Event")

	evt := ngapEvent.(*context.SendInitialContextSetupRespEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	message.SendInitialContextSetupResponse(ranUe, evt.ResponseList, evt.FailedList, evt.CriticalityDiagnostics)
}

func HandleSendSendUEContextRelease(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendSendUEContextRelease Event")

	evt := ngapEvent.(*context.SendUEContextReleaseEvt)
	ranUeNgapId := evt.RanUeNgapId
	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	if ranUe.GetSharedCtx().UeCtxRelState {
		if err := ranUe.Remove(); err != nil {
			logger.NgapLog.Errorf("delete RanUe Context error: %v", err)
		}
		message.SendUEContextReleaseComplete(ranUe, nil)
		ranUe.GetSharedCtx().UeCtxRelState = context.UeCtxRelStateNone
	} else {
		cause := message.BuildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
		message.SendUEContextReleaseRequest(ranUe, *cause)
		ranUe.GetSharedCtx().UeCtxRelState = context.UeCtxRelStateOngoing
	}
}

func HandleSendSendPDUSessionResourceRelease(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendSendPDUSessionResourceRelease Event")

	evt := ngapEvent.(*context.SendPDUSessionResourceReleaseEvt)
	ranUeNgapId := evt.RanUeNgapId
	deletPduIds := evt.DeletePduIds
	n3iwfCtx := context.N3IWFSelf()
	ranUe, ok := n3iwfCtx.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	if ranUe.GetSharedCtx().PduSessResRelState {
		message.SendPDUSessionResourceReleaseResponse(ranUe, ranUe.GetSharedCtx().PduSessionReleaseList, nil)
		ranUe.GetSharedCtx().PduSessResRelState = context.PduSessResRelStateNone
	} else {
		for _, id := range deletPduIds {
			ranUe.GetSharedCtx().DeletePDUSession(id)
		}
		ranUe.GetSharedCtx().PduSessResRelState = context.PduSessResRelStateOngoing
	}
}
