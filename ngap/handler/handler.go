// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/aper"
	"github.com/omec-project/n3iwf/context"
	gtp_service "github.com/omec-project/n3iwf/gtp/service"
	"github.com/omec-project/n3iwf/ike/handler"
	ike_message "github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	ngap_message "github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/ngap/ngapConvert"
	"github.com/omec-project/ngap/ngapType"
)

func HandleNGSetupResponse(sctpAddr string, conn *sctp.SCTPConn, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Setup Response")

	var amfName *ngapType.AMFName
	var servedGUAMIList *ngapType.ServedGUAMIList
	var relativeAMFCapacity *ngapType.RelativeAMFCapacity
	var plmnSupportList *ngapType.PLMNSupportList
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := message.SuccessfulOutcome
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

		cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		procedureCode := ngapType.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentSuccessfulOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		ngap_message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)

		return
	}

	amfInfo := n3iwfSelf.NewN3iwfAmf(sctpAddr, conn)

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

func HandleNGSetupFailure(sctpAddr string, conn *sctp.SCTPConn, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Setup Failure")

	var cause *ngapType.Cause
	var timeToWait *ngapType.TimeToWait
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	unsuccessfulOutcome := message.UnsuccessfulOutcome
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

		cause = buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

		procedureCode := ngapType.ProcedureCodeNGSetup
		triggeringMessage := ngapType.TriggeringMessagePresentUnsuccessfullOutcome
		procedureCriticality := ngapType.CriticalityPresentReject

		criticalityDiagnostics := buildCriticalityDiagnostics(
			&procedureCode, &triggeringMessage, &procedureCriticality, &iesCriticalityDiagnostics)

		ngap_message.SendErrorIndicationWithSctpConn(conn, nil, nil, cause, &criticalityDiagnostics)

		return
	}

	if cause != nil {
		printAndGetCause(cause)
	}

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
		n3iwfSelf.AMFReInitAvailableListStore(sctpAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			n3iwfSelf.AMFReInitAvailableListStore(sctpAddr, true)
			ngap_message.SendNGSetupRequest(conn)
		})
		return
	}
}

func HandleNGReset(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Reset")

	var cause *ngapType.Cause
	var resetType *ngapType.ResetType

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	n3iwfSelf := context.N3IWFSelf()

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		ngap_message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	printAndGetCause(cause)

	switch resetType.Present {
	case ngapType.ResetTypePresentNGInterface:
		logger.NgapLog.Debugln("ResetType Present: NG Interface")
		// TODO: Release Uu Interface related to this amf(IPSec)
		// Remove all Ue
		amf.RemoveAllRelatedUe()
		ngap_message.SendNGResetAcknowledge(amf, nil, nil)
	case ngapType.ResetTypePresentPartOfNGInterface:
		logger.NgapLog.Debugln("ResetType Present: Part of NG Interface")

		partOfNGInterface := resetType.PartOfNGInterface
		if partOfNGInterface == nil {
			logger.NgapLog.Errorln("PartOfNGInterface is nil")
			return
		}

		var ue *context.N3IWFUe

		for _, ueAssociatedLogicalNGConnectionItem := range partOfNGInterface.List {
			if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
				logger.NgapLog.Debugf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				ue, _ = n3iwfSelf.UePoolLoad(ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
			} else if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
				logger.NgapLog.Debugf("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				ue = amf.FindUeByAmfUeNgapID(ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
			}

			if ue == nil {
				logger.NgapLog.Warnln("cannot not find UE Context")
				if ueAssociatedLogicalNGConnectionItem.AMFUENGAPID != nil {
					logger.NgapLog.Warnf("AmfUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.AMFUENGAPID.Value)
				}
				if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
					logger.NgapLog.Warnf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				}
				continue
			}
			// TODO: Release Uu Interface (IPSec)
			ue.Remove()
		}
		ngap_message.SendNGResetAcknowledge(amf, partOfNGInterface, nil)
	default:
		logger.NgapLog.Warnf("invalid ResetType[%d]", resetType.Present)
	}
}

func HandleNGResetAcknowledge(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle NG Reset Acknowledge")

	var uEAssociatedLogicalNGConnectionList *ngapType.UEAssociatedLogicalNGConnectionList
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := message.SuccessfulOutcome
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
		logger.NgapLog.Debugf("%d UE association(s) has been reset", len(uEAssociatedLogicalNGConnectionList.List))
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

func HandleInitialContextSetupRequest(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	var n3iwfUe *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		cause := buildCause(ngapType.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

		failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
		for _, item := range pduSessionResourceSetupListCxtReq.List {
			transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			ngap_message.AppendPDUSessionResourceFailedToSetupListCxtfail(
				failedListCxtFail, item.PDUSessionID.Value, transfer)
		}

		ngap_message.SendInitialContextSetupFailure(amf, n3iwfUe, *cause, failedListCxtFail, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		} else {
			if n3iwfUe.AmfUeNgapId != amfUeNgapID.Value {
				// TODO: build cause and handle error
				// Cause: Inconsistent remote UE NGAP ID
				return
			}
		}
	}

	n3iwfUe.AmfUeNgapId = amfUeNgapID.Value
	n3iwfUe.RanUeNgapId = ranUeNgapID.Value

	if pduSessionResourceSetupListCxtReq != nil {
		if ueAggregateMaximumBitRate != nil {
			n3iwfUe.Ambr = ueAggregateMaximumBitRate
		} else {
			logger.NgapLog.Errorln("IE[UEAggregateMaximumBitRate] is nil")
			cause := buildCause(ngapType.CausePresentProtocol,
				ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)

			criticalityDiagnosticsIEItem := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject,
				ngapType.ProtocolIEIDUEAggregateMaximumBitRate, ngapType.TypeOfErrorPresentMissing)
			iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, criticalityDiagnosticsIEItem)
			criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)

			failedListCxtFail := new(ngapType.PDUSessionResourceFailedToSetupListCxtFail)
			for _, item := range pduSessionResourceSetupListCxtReq.List {
				transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				ngap_message.AppendPDUSessionResourceFailedToSetupListCxtfail(
					failedListCxtFail, item.PDUSessionID.Value, transfer)
			}

			ngap_message.SendInitialContextSetupFailure(amf, n3iwfUe, *cause, failedListCxtFail, &criticalityDiagnostics)
			return
		}

		setupListCxtRes := new(ngapType.PDUSessionResourceSetupListCxtRes)
		failedListCxtRes := new(ngapType.PDUSessionResourceFailedToSetupListCxtRes)
		// UE temporary data for PDU session setup response
		n3iwfUe.TemporaryPDUSessionSetupData = &context.PDUSessionSetupTemporaryData{
			SetupListCxtRes:  setupListCxtRes,
			FailedListCxtRes: failedListCxtRes,
		}
		n3iwfUe.TemporaryPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup

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

			pduSession, err := n3iwfUe.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := buildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(
					failedListCxtRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(n3iwfUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession = append(n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession, pduSessionID)
			} else {
				// Delete the pdusession store in UE conext
				delete(n3iwfUe.PduSessionList, pduSessionID)
				ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(failedListCxtRes, pduSessionID, resTransfer)
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if guami != nil {
		n3iwfUe.Guami = guami
	}

	if allowedNSSAI != nil {
		n3iwfUe.AllowedNssai = allowedNSSAI
	}

	if maskedIMEISV != nil {
		n3iwfUe.MaskedIMEISV = maskedIMEISV
	}

	if ueRadioCapability != nil {
		n3iwfUe.RadioCapability = ueRadioCapability
	}

	if coreNetworkAssistanceInformation != nil {
		n3iwfUe.CoreNetworkAssistanceInformation = coreNetworkAssistanceInformation
	}

	if indexToRFSP != nil {
		n3iwfUe.IndexToRfsp = indexToRFSP.Value
	}

	if ueSecurityCapabilities != nil {
		n3iwfUe.SecurityCapabilities = ueSecurityCapabilities
	}

	if securityKey != nil {
		n3iwfUe.Kn3iwf = securityKey.Value.Bytes
	}

	// if nasPDU != nil {
	// TODO: Send NAS UE
	// }

	// Send EAP Success to UE
	ikeSecurityAssociation := n3iwfUe.N3IWFIKESecurityAssociation
	responseIKEMessage := new(ike_message.IKEMessage)
	var responseIKEPayload ike_message.IKEPayloadContainer

	// Build IKE message
	responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI,
		ikeSecurityAssociation.LocalSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck,
		ikeSecurityAssociation.MessageID)
	responseIKEMessage.Payloads.Reset()

	// EAP Success
	var identifier uint8
	for {
		identifier = uint8(rand.Uint32())
		if identifier != ikeSecurityAssociation.LastEAPIdentifier {
			ikeSecurityAssociation.LastEAPIdentifier = identifier
			break
		}
	}
	responseIKEPayload.BuildEAPSuccess(identifier)

	if err := handler.EncryptProcedure(ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
		logger.NgapLog.Errorf("encrypting IKE message failed: %+v", err)
		return
	}

	n3iwfUe.N3IWFIKESecurityAssociation.State++

	// Send IKE message to UE
	handler.SendIKEMessageToUE(n3iwfUe.IKEConnection.Conn, n3iwfUe.IKEConnection.N3IWFAddr,
		n3iwfUe.IKEConnection.UEAddr, responseIKEMessage)
}

// handlePDUSessionResourceSetupRequestTransfer parse and store needed information from NGAP
// and setup user plane connection for UE
// Parameters:
// UE context :: a pointer to the UE's pdusession data structure ::
// SMF PDU session resource setup request transfer
// Return value:
// a status value indicates whether the handling is "success" ::
// if failed, an unsuccessfulTransfer is set, otherwise, set to nil
func handlePDUSessionResourceSetupRequestTransfer(ue *context.N3IWFUe, pduSession *context.PDUSession,
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
		cause := buildCause(ngapType.CausePresentProtocol,
			ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, &criticalityDiagnostics)
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
			pduSession.SecurityIntegrity = false
		case ngapType.IntegrityProtectionIndicationPresentPreferred:
			pduSession.SecurityIntegrity = true
		case ngapType.IntegrityProtectionIndicationPresentRequired:
			pduSession.SecurityIntegrity = true
		default:
			logger.NgapLog.Errorln("unknown security integrity indication")
			cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}

		switch securityIndication.ConfidentialityProtectionIndication.Value {
		case ngapType.ConfidentialityProtectionIndicationPresentNotNeeded:
			pduSession.SecurityCipher = false
		case ngapType.ConfidentialityProtectionIndicationPresentPreferred:
			pduSession.SecurityCipher = true
		case ngapType.ConfidentialityProtectionIndicationPresentRequired:
			pduSession.SecurityCipher = true
		default:
			logger.NgapLog.Errorln("unknown security confidentiality indication")
			cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}
	} else {
		pduSession.SecurityIntegrity = false
		pduSession.SecurityCipher = true
	}

	// TODO: apply qos rule
	for _, item := range qosFlowSetupRequestList.List {
		// QoS Flow
		qosFlow := new(context.QosFlow)
		qosFlow.Identifier = item.QosFlowIdentifier.Value
		qosFlow.Parameters = item.QosFlowLevelQosParameters
		pduSession.QosFlows[item.QosFlowIdentifier.Value] = qosFlow
		// QFI List
		pduSession.QFIList = append(pduSession.QFIList, uint8(item.QosFlowIdentifier.Value))
	}

	// Setup GTP tunnel with UPF
	// TODO: Support IPv6
	upfIPv4, _ := ngapConvert.IPAddressToString(ulNGUUPTNLInformation.GTPTunnel.TransportLayerAddress)
	if upfIPv4 != "" {
		n3iwfSelf := context.N3IWFSelf()

		gtpConnection := &context.GTPConnectionInfo{
			UPFIPAddr:    upfIPv4,
			OutgoingTEID: binary.BigEndian.Uint32(ulNGUUPTNLInformation.GTPTunnel.GTPTEID.Value),
		}

		if userPlaneConnection, ok := n3iwfSelf.GTPConnectionWithUPFLoad(upfIPv4); ok {
			// UPF UDP address
			upfUDPAddr, err := net.ResolveUDPAddr("udp", upfIPv4+":2152")
			if err != nil {
				logger.NgapLog.Errorf("resolve UDP address failed: %+v", err)
				cause := buildCause(ngapType.CausePresentTransport,
					ngapType.CauseTransportPresentTransportResourceUnavailable)
				responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				return false, responseTransfer
			}

			// UE TEID
			ueTEID := n3iwfSelf.NewTEID(ue)
			if ueTEID == 0 {
				logger.NgapLog.Errorln("invalid TEID (0)")
				cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentUnspecified)
				responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				return false, responseTransfer
			}

			// Set UE associated GTP connection
			gtpConnection.UPFUDPAddr = upfUDPAddr
			gtpConnection.IncomingTEID = ueTEID
			gtpConnection.UserPlaneConnection = userPlaneConnection
		} else {
			// Setup GTP connection with UPF
			userPlaneConnection, upfUDPAddr, err := gtp_service.SetupGTPTunnelWithUPF(upfIPv4)
			if err != nil {
				logger.NgapLog.Errorf("Setup GTP connection with UPF failed: %+v", err)
				cause := buildCause(ngapType.CausePresentTransport,
					ngapType.CauseTransportPresentTransportResourceUnavailable)
				responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				return false, responseTransfer
			}
			// Listen GTP tunnel
			if err := gtp_service.ListenAndServe(userPlaneConnection); err != nil {
				logger.NgapLog.Errorf("listening GTP tunnel failed: %+v", err)
				cause := buildCause(ngapType.CausePresentTransport,
					ngapType.CauseTransportPresentTransportResourceUnavailable)
				responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				return false, responseTransfer
			}

			// UE TEID
			ueTEID := n3iwfSelf.NewTEID(ue)
			if ueTEID == 0 {
				logger.NgapLog.Errorln("invalid TEID (0)")
				cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentUnspecified)
				responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
				}
				return false, responseTransfer
			}

			// Setup GTP connection with UPF
			gtpConnection.UPFUDPAddr = upfUDPAddr
			gtpConnection.IncomingTEID = ueTEID
			gtpConnection.UserPlaneConnection = userPlaneConnection

			// Store GTP connection with UPF into N3IWF context
			n3iwfSelf.GTPConnectionWithUPFStore(upfIPv4, userPlaneConnection)
		}

		pduSession.GTPConnection = gtpConnection
	} else {
		logger.NgapLog.Errorln("cannot parse 'PDU session resource setup request transfer' message 'UL NG-U UP TNL Information'")
		cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
		}
		return false, responseTransfer
	}

	return true, nil
}

func HandleUEContextModificationRequest(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	var n3iwfUe *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		} else {
			if n3iwfUe.AmfUeNgapId != amfUeNgapID.Value {
				// TODO: build cause and handle error
				// Cause: Inconsistent remote UE NGAP ID
				return
			}
		}
	}

	if newAmfUeNgapID != nil {
		logger.NgapLog.Debugf("new AmfUeNgapID[%d]", newAmfUeNgapID.Value)
		n3iwfUe.AmfUeNgapId = newAmfUeNgapID.Value
	}

	if ueAggregateMaximumBitRate != nil {
		n3iwfUe.Ambr = ueAggregateMaximumBitRate
		// TODO: use the received UE Aggregate Maximum Bit Rate for all non-GBR QoS flows
	}

	if ueSecurityCapabilities != nil {
		n3iwfUe.SecurityCapabilities = ueSecurityCapabilities
	}

	if securityKey != nil {
		n3iwfUe.Kn3iwf = securityKey.Value.Bytes
	}

	// TODO: use new security key to update security context

	if indexToRFSP != nil {
		n3iwfUe.IndexToRfsp = indexToRFSP.Value
	}

	ngap_message.SendUEContextModificationResponse(amf, n3iwfUe, nil)
}

func HandleUEContextReleaseCommand(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE Context Release Command")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var ueNgapIDs *ngapType.UENGAPIDs
	var cause *ngapType.Cause
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var n3iwfUe *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ueNgapIDs.UENGAPIDPair.RANUENGAPID.Value)
		if !ok {
			n3iwfUe = amf.FindUeByAmfUeNgapID(ueNgapIDs.UENGAPIDPair.AMFUENGAPID.Value)
		}
	case ngapType.UENGAPIDsPresentAMFUENGAPID:
		// TODO: find UE according to specific AMF
		// The implementation here may have error when N3IWF need to
		// connect multiple AMFs.
		// Use UEpool in AMF context can solve this problem
		n3iwfUe = amf.FindUeByAmfUeNgapID(ueNgapIDs.AMFUENGAPID.Value)
	}

	if n3iwfUe == nil {
		// TODO: send error indication(unknown local ngap ue id)
		return
	}

	if cause != nil {
		printAndGetCause(cause)
	}

	// TODO: release pdu session and gtp info for ue
	n3iwfUe.Remove()

	ngap_message.SendUEContextReleaseComplete(amf, n3iwfUe, nil)
}

func HandleDownlinkNASTransport(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	var n3iwfUe *context.N3IWFUe
	var n3iwfSelf *context.N3IWFContext = context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Warnf("no UE Context[RanUeNgapID:%d]", ranUeNgapID.Value)
			return
		}
	}

	if amfUeNgapID != nil {
		if n3iwfUe.AmfUeNgapId == context.AmfUeNgapIdUnspecified {
			logger.NgapLog.Debugln("create new logical UE-associated NG-connection")
			n3iwfUe.AmfUeNgapId = amfUeNgapID.Value
		} else {
			if n3iwfUe.AmfUeNgapId != amfUeNgapID.Value {
				logger.NgapLog.Warnln("AMFUENGAPID unmatched")
				return
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if indexToRFSP != nil {
		n3iwfUe.IndexToRfsp = indexToRFSP.Value
	}

	if ueAggregateMaximumBitRate != nil {
		n3iwfUe.Ambr = ueAggregateMaximumBitRate
	}

	if allowedNSSAI != nil {
		n3iwfUe.AllowedNssai = allowedNSSAI
	}

	if nasPDU != nil {
		// TODO: Send NAS PDU to UE
		if n3iwfUe.N3IWFChildSecurityAssociation == nil {
			var identifier uint8
			ikeSecurityAssociation := n3iwfUe.N3IWFIKESecurityAssociation

			for {
				identifier = uint8(rand.Uint32())
				if identifier != n3iwfUe.N3IWFIKESecurityAssociation.LastEAPIdentifier {
					n3iwfUe.N3IWFIKESecurityAssociation.LastEAPIdentifier = identifier
					break
				}
			}
			// Send NAS via IKE EAP
			responseIKEMessage := new(ike_message.IKEMessage)
			var responseIKEPayload ike_message.IKEPayloadContainer

			// Build IKE message
			responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.RemoteSPI,
				ikeSecurityAssociation.LocalSPI, ike_message.IKE_AUTH, ike_message.ResponseBitCheck,
				ikeSecurityAssociation.MessageID)
			responseIKEMessage.Payloads.Reset()

			// EAP-5G
			responseIKEPayload.BuildEAP5GNAS(identifier, nasPDU.Value)

			if err := handler.EncryptProcedure(
				ikeSecurityAssociation, responseIKEPayload, responseIKEMessage); err != nil {
				logger.NgapLog.Errorf("encrypting IKE message failed: %+v", err)
				return
			}

			// Send IKE message to UE
			handler.SendIKEMessageToUE(n3iwfUe.IKEConnection.Conn, n3iwfUe.IKEConnection.N3IWFAddr,
				n3iwfUe.IKEConnection.UEAddr, responseIKEMessage)
		} else {
			// Check ue.TCPConnection. If failed, retry 2 times.
			maxRetryTimes := 3
			for i := 0; i < maxRetryTimes; i++ {
				if n3iwfUe.TCPConnection == nil {
					if i == (maxRetryTimes - 1) {
						logger.NgapLog.Warnln(
							"no connection found for UE to send NAS message. This message will be cached in N3IWF")
						n3iwfUe.TemporaryCachedNASMessage = nasPDU.Value
						return
					} else {
						logger.NgapLog.Warnln("no NAS signalling session found, retry...")
					}
					time.Sleep(500 * time.Millisecond)
				} else {
					break
				}
			}

			// Send to UE
			if n, err := n3iwfUe.TCPConnection.Write(nasPDU.Value); err != nil {
				logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", err)
			} else {
				logger.NgapLog.Debugln("forward NWu <- N2")
				logger.NgapLog.Debugf("wrote %d bytes", n)
			}
		}
	}
}

func HandlePDUSessionResourceSetupRequest(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	var n3iwfUe *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		} else {
			if n3iwfUe.AmfUeNgapId != amfUeNgapID.Value {
				// TODO: build cause and handle error
				// Cause: Inconsistent remote UE NGAP ID
				return
			}
		}
	}

	if nasPDU != nil {
		// TODO: Send NAS to UE
		if n3iwfUe.TCPConnection == nil {
			logger.NgapLog.Errorln("no IPSec NAS signalling SA for this UE")
			return
		} else {
			if n, err := n3iwfUe.TCPConnection.Write(nasPDU.Value); err != nil {
				logger.NgapLog.Errorf("send NAS to UE failed: %+v", err)
				return
			} else {
				logger.NgapLog.Debugf("wrote %d bytes", n)
			}
		}
	}

	if pduSessionResourceSetupListSUReq != nil {
		setupListSURes := new(ngapType.PDUSessionResourceSetupListSURes)
		failedListSURes := new(ngapType.PDUSessionResourceFailedToSetupListSURes)
		// UE temporary data for PDU session setup response
		n3iwfUe.TemporaryPDUSessionSetupData = &context.PDUSessionSetupTemporaryData{
			SetupListSURes:  setupListSURes,
			FailedListSURes: failedListSURes,
		}
		n3iwfUe.TemporaryPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup

		for _, item := range pduSessionResourceSetupListSUReq.List {
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

			pduSession, err := n3iwfUe.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := buildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(n3iwfUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession = append(n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession, pduSessionID)
			} else {
				// Delete the pdusession store in UE conext
				delete(n3iwfUe.PduSessionList, pduSessionID)
				ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, resTransfer)
			}
		}
	}

	if n3iwfUe.TemporaryPDUSessionSetupData != nil {
		for {
			if len(n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession) != 0 {
				pduSessionID := n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession[0]
				pduSession := n3iwfUe.PduSessionList[pduSessionID]

				ikeSecurityAssociation := n3iwfUe.N3IWFIKESecurityAssociation

				// Add MessageID for IKE security association
				ikeSecurityAssociation.MessageID++

				// Send CREATE_CHILD_SA to UE
				ikeMessage := new(ike_message.IKEMessage)
				var ikePayload ike_message.IKEPayloadContainer

				// Build IKE message
				ikeMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI,
					ikeSecurityAssociation.RemoteSPI, ike_message.CREATE_CHILD_SA,
					ike_message.InitiatorBitCheck, ikeSecurityAssociation.MessageID)
				ikeMessage.Payloads.Reset()

				// Build SA
				requestSA := ikePayload.BuildSecurityAssociation()

				// Allocate SPI
				var spi uint32
				spiByte := make([]byte, 4)
				for {
					randomUint64 := handler.GenerateRandomNumber().Uint64()
					if _, ok := n3iwfSelf.ChildSA.Load(uint32(randomUint64)); !ok {
						spi = uint32(randomUint64)
						break
					}
				}
				binary.BigEndian.PutUint32(spiByte, spi)

				// First Proposal - Proposal No.1
				proposal := requestSA.Proposals.BuildProposal(1, ike_message.TypeESP, spiByte)

				// Encryption transform
				var attributeType uint16 = ike_message.AttributeTypeKeyLength
				var attributeValue uint16 = 256
				proposal.EncryptionAlgorithm.BuildTransform(
					ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_AES_CBC, &attributeType, &attributeValue, nil)
				// Integrity transform
				if pduSession.SecurityIntegrity {
					proposal.IntegrityAlgorithm.BuildTransform(
						ike_message.TypeIntegrityAlgorithm, ike_message.AUTH_HMAC_SHA1_96, nil, nil, nil)
				}
				// ESN transform
				proposal.ExtendedSequenceNumbers.BuildTransform(
					ike_message.TypeExtendedSequenceNumbers, ike_message.ESN_NO, nil, nil, nil)

				// Build Nonce
				nonceData := handler.GenerateRandomNumber().Bytes()
				ikePayload.BuildNonce(nonceData)

				// Store nonce into context
				ikeSecurityAssociation.ConcatenatedNonce = nonceData

				// TSi
				n3iwfIPAddr := net.ParseIP(n3iwfSelf.IPSecGatewayAddress)
				tsi := ikePayload.BuildTrafficSelectorInitiator()
				tsi.TrafficSelectors.BuildIndividualTrafficSelector(
					ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
					0, 65535, n3iwfIPAddr.To4(), n3iwfIPAddr.To4())
				// TSr
				ueIPAddr := n3iwfUe.IPSecInnerIP
				tsr := ikePayload.BuildTrafficSelectorResponder()
				tsr.TrafficSelectors.BuildIndividualTrafficSelector(
					ike_message.TS_IPV4_ADDR_RANGE, ike_message.IPProtocolAll,
					0, 65535, ueIPAddr.To4(), ueIPAddr.To4())

				// Notify-Qos
				ikePayload.BuildNotify5G_QOS_INFO(uint8(pduSessionID), pduSession.QFIList, true, false, 0)

				// Notify-UP_IP_ADDRESS
				ikePayload.BuildNotifyUP_IP4_ADDRESS(n3iwfSelf.IPSecGatewayAddress)

				if err := handler.EncryptProcedure(
					n3iwfUe.N3IWFIKESecurityAssociation, ikePayload, ikeMessage); err != nil {
					logger.NgapLog.Errorf("encrypting IKE message failed: %+v", err)
					n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession = n3iwfUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession[1:]
					cause := buildCause(ngapType.CausePresentTransport, ngapType.CauseTransportPresentTransportResourceUnavailable)
					transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
					if err != nil {
						logger.NgapLog.Errorf("build PDU Session Resource Setup Unsuccessful Transfer Failed: %+v", err)
						continue
					}
					ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(n3iwfUe.TemporaryPDUSessionSetupData.FailedListSURes,
						pduSessionID, transfer)
					continue
				}

				handler.SendIKEMessageToUE(n3iwfUe.IKEConnection.Conn, n3iwfUe.IKEConnection.N3IWFAddr,
					n3iwfUe.IKEConnection.UEAddr, ikeMessage)
				break
			} else {
				// Send PDU Session Resource Setup Response to AMF
				ngap_message.SendPDUSessionResourceSetupResponse(amf, n3iwfUe,
					n3iwfUe.TemporaryPDUSessionSetupData.SetupListSURes, n3iwfUe.TemporaryPDUSessionSetupData.FailedListSURes, nil)
				break
			}
		}
	}
}

func HandlePDUSessionResourceModifyRequest(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Modify Request")

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}

	var amfUeNgapID *ngapType.AMFUENGAPID
	var ranUeNgapID *ngapType.RANUENGAPID
	var pduSessionResourceModifyListModReq *ngapType.PDUSessionResourceModifyListModReq
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	var n3iwfUe *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		ngap_message.SendPDUSessionResourceModifyResponse(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		n3iwfUe, ok = n3iwfSelf.UePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and send error indication
			// Cause: Unknown local UE NGAP ID
			return
		} else {
			if n3iwfUe.AmfUeNgapId != amfUeNgapID.Value {
				// TODO: build cause and send error indication
				// Cause: Inconsistent remote UE NGAP ID
				return
			}
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

			if pduSession = n3iwfUe.FindPDUSession(pduSessionID); pduSession == nil {
				logger.NgapLog.Errorf("[PDUSessionID: %d] Unknown PDU session ID", pduSessionID)

				cause := buildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
				unsuccessfulTransfer, buildErr := ngap_message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceModifyUnsuccessfulTransfer Error: %+v", buildErr)
				}
				ngap_message.AppendPDUSessionResourceFailedToModifyListModRes(failedListModRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceModifyRequestTransfer(pduSession, transfer)
			if success {
				ngap_message.AppendPDUSessionResourceModifyListModRes(responseList, pduSessionID, resTransfer)
			} else {
				ngap_message.AppendPDUSessionResourceFailedToModifyListModRes(failedListModRes, pduSessionID, resTransfer)
			}
		}
	}

	ngap_message.SendPDUSessionResourceModifyResponse(amf, n3iwfUe, responseList, failedListModRes, nil)
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
		cause := buildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		unsuccessfulTransfer, err := ngap_message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, &criticalityDiagnostics)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceModifyUnsuccessfulTransfer Error: %+v", err)
		}

		success = false
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

				cause := buildCause(
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

	encodeData, err := ngap_message.BuildPDUSessionResourceModifyResponseTransfer(
		resULNGUUPTNLInfo, resDLNGUUPTNLInfo, &resQosFlowAddOrModifyRequestList, &resQosFlowFailedToAddOrModifyList)
	if err != nil {
		logger.NgapLog.Errorf("build PDUSessionResourceModifyTransfer Error: %+v", err)
	}

	success = true
	responseTransfer = encodeData

	return success, responseTransfer
}

func HandlePDUSessionResourceModifyConfirm(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle PDU Session Resource Modify Confirm")

	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var pDUSessionResourceModifyListModCfm *ngapType.PDUSessionResourceModifyListModCfm
	var pDUSessionResourceFailedToModifyListModCfm *ngapType.PDUSessionResourceFailedToModifyListModCfm
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	// var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := message.SuccessfulOutcome
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

	var ue *context.N3IWFUe
	n3iwfSelf := context.N3IWFSelf()

	if rANUENGAPID != nil {
		var ok bool
		ue, ok = n3iwfSelf.UePoolLoad(rANUENGAPID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
			return
		}
	}
	if aMFUENGAPID != nil {
		if ue != nil {
			if ue.AmfUeNgapId != aMFUENGAPID.Value {
				logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, ue.AmfUeNgapId: %d",
					aMFUENGAPID.Value, ue.AmfUeNgapId)
				return
			}
		} else {
			ue = amf.FindUeByAmfUeNgapID(aMFUENGAPID.Value)
			if ue == nil {
				logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d", aMFUENGAPID.Value)
				return
			}
		}
	}
	if ue == nil {
		logger.NgapLog.Warnln("RANUENGAPID and AMFUENGAPID are both nil")
		return
	}
	if pDUSessionResourceModifyListModCfm != nil {
		for _, item := range pDUSessionResourceModifyListModCfm.List {
			pduSessionId := item.PDUSessionID.Value
			logger.NgapLog.Debugf("PDU Session Id[%d] in Pdu Session Resource Modification Confrim List", pduSessionId)
			sess, exist := ue.PduSessionList[pduSessionId]
			if !exist {
				logger.NgapLog.Warnf("PDU Session Id[%d] is not exist in Ue[ranUeNgapId:%d]", pduSessionId, ue.RanUeNgapId)
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
			delete(ue.PduSessionList, pduSessionId)
		}
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}
}

func HandlePDUSessionResourceReleaseCommand(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		ngap_message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	n3iwfSelf := context.N3IWFSelf()
	ue, ok := n3iwfSelf.UePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := buildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	if ue.AmfUeNgapId != aMFUENGAPID.Value {
		logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, ue.AmfUeNgapId: %d",
			aMFUENGAPID.Value, ue.AmfUeNgapId)
		cause := buildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, &rANUENGAPID.Value, cause, nil)
		return
	}

	// if rANPagingPriority != nil {
	// n3iwf does not support paging
	// }

	releaseList := ngapType.PDUSessionResourceReleasedListRelRes{}
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
		delete(ue.PduSessionList, pduSessionId)

		// response list
		releaseItem := ngapType.PDUSessionResourceReleasedItemRelRes{
			PDUSessionID: item.PDUSessionID,
			PDUSessionResourceReleaseResponseTransfer: getPDUSessionResourceReleaseResponseTransfer(),
		}
		releaseList.List = append(releaseList.List, releaseItem)
	}

	// if nASPDU != nil {
	// TODO: Send NAS to UE
	// }
	ngap_message.SendPDUSessionResourceReleaseResponse(amf, ue, releaseList, nil)
}

func HandleErrorIndication(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Error Indication")

	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var cause *ngapType.Cause
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("corresponding AMF context not found")
		return
	}
	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}
	initiatingMessage := message.InitiatingMessage
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

	if cause != nil {
		printAndGetCause(cause)
	}

	if criticalityDiagnostics != nil {
		printCriticalityDiagnostics(criticalityDiagnostics)
	}

	// TODO: handle error based on cause/criticalityDiagnostics
}

func HandleUERadioCapabilityCheckRequest(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE Radio Capability Check Request")
	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var uERadioCapability *ngapType.UERadioCapability

	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
		ngap_message.SendErrorIndication(amf, nil, nil, nil, &criticalityDiagnostics)
		return
	}

	n3iwfSelf := context.N3IWFSelf()
	ue, ok := n3iwfSelf.UePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := buildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	ue.RadioCapability = uERadioCapability
}

func HandleAMFConfigurationUpdate(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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
	ngap_message.SendAMFConfigurationUpdateAcknowledge(amf, setupList, nil, nil)
}

func HandleRANConfigurationUpdateAcknowledge(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle RAN Configuration Update Acknowledge")

	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	successfulOutcome := message.SuccessfulOutcome
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

func HandleRANConfigurationUpdateFailure(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle RAN Configuration Update Failure")

	var cause *ngapType.Cause
	var timeToWait *ngapType.TimeToWait
	var criticalityDiagnostics *ngapType.CriticalityDiagnostics

	n3iwfSelf := context.N3IWFSelf()

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	unsuccessfulOutcome := message.UnsuccessfulOutcome
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

	if cause != nil {
		printAndGetCause(cause)
	}

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
		logger.NgapLog.Infof("wait at lease  %ds to resend RAN Configuration Update to same AMF[%s]",
			waitingTime, amf.SCTPAddr)
		n3iwfSelf.AMFReInitAvailableListStore(amf.SCTPAddr, false)
		time.AfterFunc(time.Duration(waitingTime)*time.Second, func() {
			logger.NgapLog.Infoln("re-send Ran Configuration Update Message when waiting time expired")
			n3iwfSelf.AMFReInitAvailableListStore(amf.SCTPAddr, true)
			ngap_message.SendRANConfigurationUpdate(amf)
		})
		return
	}
	ngap_message.SendRANConfigurationUpdate(amf)
}

func HandleDownlinkRANConfigurationTransfer(message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Downlink RAN Configuration Transfer")
}

func HandleDownlinkRANStatusTransfer(message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Downlink RAN Status Transfer")
}

func HandleAMFStatusIndication(message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle AMF Status Indication")
}

func HandleLocationReportingControl(message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Location Reporting Control")
}

func HandleUETNLAReleaseRequest(message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle UE TNLA Release Request")
}

func HandleOverloadStart(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
	logger.NgapLog.Infoln("handle Overload Start")

	var aMFOverloadResponse *ngapType.OverloadResponse
	var aMFTrafficLoadReductionIndication *ngapType.TrafficLoadReductionIndication
	var overloadStartNSSAIList *ngapType.OverloadStartNSSAIList

	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil")
		return
	}

	if message == nil {
		logger.NgapLog.Errorln("NGAP Message is nil")
		return
	}

	initiatingMessage := message.InitiatingMessage
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

func HandleOverloadStop(amf *context.N3IWFAMF, message *ngapType.NGAPPDU) {
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

func buildCause(present int, value aper.Enumerated) (cause *ngapType.Cause) {
	cause = new(ngapType.Cause)
	cause.Present = present

	switch present {
	case ngapType.CausePresentRadioNetwork:
		cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
		cause.RadioNetwork.Value = value
	case ngapType.CausePresentTransport:
		cause.Transport = new(ngapType.CauseTransport)
		cause.Transport.Value = value
	case ngapType.CausePresentNas:
		cause.Nas = new(ngapType.CauseNas)
		cause.Nas.Value = value
	case ngapType.CausePresentProtocol:
		cause.Protocol = new(ngapType.CauseProtocol)
		cause.Protocol.Value = value
	case ngapType.CausePresentMisc:
		cause.Misc = new(ngapType.CauseMisc)
		cause.Misc.Value = value
	case ngapType.CausePresentNothing:
	}

	return
}

func printAndGetCause(cause *ngapType.Cause) (present int, value aper.Enumerated) {
	present = cause.Present
	switch cause.Present {
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
		logger.NgapLog.Errorf("invalid Cause group[%d]", cause.Present)
	}
	return
}

func printCriticalityDiagnostics(criticalityDiagnostics *ngapType.CriticalityDiagnostics) {
	if criticalityDiagnostics == nil {
		return
	} else {
		iesCriticalityDiagnostics := criticalityDiagnostics.IEsCriticalityDiagnostics
		if iesCriticalityDiagnostics != nil {
			for index, item := range iesCriticalityDiagnostics.List {
				logger.NgapLog.Warnf("criticality IE item %d:", index+1)
				logger.NgapLog.Warnf("IE ID: %d", item.IEID.Value)

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
		} else {
			logger.NgapLog.Errorln("IEsCriticalityDiagnostics is nil")
		}
		return
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
