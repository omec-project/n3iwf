// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/binary"
	"net"
	"time"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/aper"
	"github.com/omec-project/n3iwf/context"
	gtp_service "github.com/omec-project/n3iwf/gtp/service"
	"github.com/omec-project/n3iwf/logger"
	ngap_message "github.com/omec-project/n3iwf/ngap/message"
	"github.com/omec-project/ngap/ngapConvert"
	"github.com/omec-project/ngap/ngapType"
)

var (
	defaultSecurityIntegrity bool = true
	defaultSecurityCipher    bool = true
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

		cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

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

		cause = ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)

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
		if err := amf.RemoveAllRelatedUe(); err != nil {
			logger.NgapLog.Errorf("remove all related UE error: %+v", err)
		}
		ngap_message.SendNGResetAcknowledge(amf, nil, nil)
	case ngapType.ResetTypePresentPartOfNGInterface:
		logger.NgapLog.Debugln("ResetType Present: Part of NG Interface")

		partOfNGInterface := resetType.PartOfNGInterface
		if partOfNGInterface == nil {
			logger.NgapLog.Errorln("PartOfNGInterface is nil")
			return
		}

		var ranUe *context.N3IWFRanUe

		for _, ueAssociatedLogicalNGConnectionItem := range partOfNGInterface.List {
			if ueAssociatedLogicalNGConnectionItem.RANUENGAPID != nil {
				logger.NgapLog.Debugf("RanUeNgapID[%d]", ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
				ranUe, _ = n3iwfSelf.RanUePoolLoad(ueAssociatedLogicalNGConnectionItem.RANUENGAPID.Value)
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

	var ranUe *context.N3IWFRanUe
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
		cause := ngap_message.BuildCause(ngapType.CausePresentProtocol,
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

		ngap_message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		if ranUe.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if ranUe == nil {
		logger.NgapLog.Errorln("RAN UE context is nil")
		return
	}

	ranUe.AmfUeNgapId = amfUeNgapID.Value
	ranUe.RanUeNgapId = ranUeNgapID.Value

	if pduSessionResourceSetupListCxtReq != nil {
		if ueAggregateMaximumBitRate == nil {
			logger.NgapLog.Errorln("IE[UEAggregateMaximumBitRate] is nil")
			cause := ngap_message.BuildCause(ngapType.CausePresentProtocol,
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

			ngap_message.SendInitialContextSetupFailure(ranUe, *cause, failedListCxtFail, &criticalityDiagnostics)
			return
		}
		ranUe.Ambr = ueAggregateMaximumBitRate

		setupListCxtRes := new(ngapType.PDUSessionResourceSetupListCxtRes)
		failedListCxtRes := new(ngapType.PDUSessionResourceFailedToSetupListCxtRes)
		// UE temporary data for PDU session setup response
		ranUe.TemporaryPDUSessionSetupData.SetupListCxtRes = setupListCxtRes
		ranUe.TemporaryPDUSessionSetupData.FailedListCxtRes = failedListCxtRes
		ranUe.TemporaryPDUSessionSetupData.Index = 0
		ranUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession = nil
		ranUe.TemporaryPDUSessionSetupData.NGAPProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup

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

			pduSession, err := ranUe.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(
					failedListCxtRes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				ranUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession = append(
					ranUe.TemporaryPDUSessionSetupData.UnactivatedPDUSession, pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUe.PduSessionList, pduSessionID)
				ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(failedListCxtRes, pduSessionID, resTransfer)
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if guami != nil {
		ranUe.Guami = guami
	}

	if allowedNSSAI != nil {
		ranUe.AllowedNssai = allowedNSSAI
	}

	if maskedIMEISV != nil {
		ranUe.MaskedIMEISV = maskedIMEISV
	}

	if ueRadioCapability != nil {
		ranUe.RadioCapability = ueRadioCapability
	}

	if coreNetworkAssistanceInformation != nil {
		ranUe.CoreNetworkAssistanceInformation = coreNetworkAssistanceInformation
	}

	if indexToRFSP != nil {
		ranUe.IndexToRfsp = indexToRFSP.Value
	}

	if ueSecurityCapabilities != nil {
		ranUe.SecurityCapabilities = ueSecurityCapabilities
	}

	spi, ok := n3iwfSelf.IkeSpiLoad(ranUe.RanUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("SPI lookup failed for NGAP ID %d: SPI is required to send EAP Success message to UE. Critical operation cannot proceed", ranUe.RanUeNgapId)
		return
	}

	// Send EAP Success to UE
	n3iwfSelf.IkeServer.RcvEventCh <- context.NewSendEAPSuccessMsgEvt(spi, securityKey.Value.Bytes,
		len(ranUe.PduSessionList))
}

// handlePDUSessionResourceSetupRequestTransfer parse and store needed information from NGAP
// and setup user plane connection for UE
// Parameters:
// UE context :: a pointer to the UE's pdusession data structure ::
// SMF PDU session resource setup request transfer
// Return value:
// a status value indicates whether the handling is "success" ::
// if failed, an unsuccessfulTransfer is set, otherwise, set to nil
func handlePDUSessionResourceSetupRequestTransfer(ranUe *context.N3IWFRanUe, pduSession *context.PDUSession,
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
		cause := ngap_message.BuildCause(ngapType.CausePresentProtocol,
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
			pduSession.SecurityIntegrity = !defaultSecurityIntegrity
		case ngapType.IntegrityProtectionIndicationPresentPreferred:
			pduSession.SecurityIntegrity = defaultSecurityIntegrity
		case ngapType.IntegrityProtectionIndicationPresentRequired:
			pduSession.SecurityIntegrity = defaultSecurityIntegrity
		default:
			logger.NgapLog.Errorln("unknown security integrity indication")
			cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
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
			cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentSemanticError)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
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
		// QFI List
		pduSession.QFIList = append(pduSession.QFIList, uint8(item.QosFlowIdentifier.Value))
	}

	// Setup GTP tunnel with UPF
	// TODO: Support IPv6
	upfIPv4, _ := ngapConvert.IPAddressToString(ulNGUUPTNLInformation.GTPTunnel.TransportLayerAddress)
	if upfIPv4 == "" {
		logger.NgapLog.Errorln("cannot parse 'PDU session resource setup request transfer' message 'UL NG-U UP TNL Information'")
		cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
		if err != nil {
			logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
		}
		return false, responseTransfer
	}

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
			cause := ngap_message.BuildCause(ngapType.CausePresentTransport,
				ngapType.CauseTransportPresentTransportResourceUnavailable)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}

		// UE TEID
		ueTEID := n3iwfSelf.NewTEID(ranUe)
		if ueTEID == 0 {
			logger.NgapLog.Errorln("invalid TEID (0)")
			cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentUnspecified)
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
			cause := ngap_message.BuildCause(ngapType.CausePresentTransport,
				ngapType.CauseTransportPresentTransportResourceUnavailable)
			responseTransfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
			if err != nil {
				logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", err)
			}
			return false, responseTransfer
		}

		// UE TEID
		ueTEID := n3iwfSelf.NewTEID(ranUe)
		if ueTEID == 0 {
			logger.NgapLog.Errorln("invalid TEID (0)")
			cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentUnspecified)
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

	var ranUe *context.N3IWFRanUe
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
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		if ranUe.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if newAmfUeNgapID != nil {
		logger.NgapLog.Debugf("new AmfUeNgapID[%d]", newAmfUeNgapID.Value)
		ranUe.AmfUeNgapId = newAmfUeNgapID.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUe.Ambr = ueAggregateMaximumBitRate
		// TODO: use the received UE Aggregate Maximum Bit Rate for all non-GBR QoS flows
	}

	if ueSecurityCapabilities != nil {
		ranUe.SecurityCapabilities = ueSecurityCapabilities
	}

	// TODO: use new security key to update security context

	if indexToRFSP != nil {
		ranUe.IndexToRfsp = indexToRFSP.Value
	}

	ngap_message.SendUEContextModificationResponse(ranUe, nil)

	spi, ok := n3iwfSelf.IkeSpiLoad(ranUe.RanUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get spi from ngapid: %d", ranUe.RanUeNgapId)
		return
	}

	n3iwfSelf.IkeServer.RcvEventCh <- context.NewIKEContextUpdateEvt(spi,
		securityKey.Value.Bytes) // Kn3iwf
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

	var ranUe *context.N3IWFRanUe
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
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ueNgapIDs.UENGAPIDPair.RANUENGAPID.Value)
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

	if cause != nil {
		printAndGetCause(cause)
	}

	localSPI, ok := n3iwfSelf.IkeSpiLoad(ranUe.RanUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get SPI from RanUeNgapID: %+v", ranUe.RanUeNgapId)
		return
	}

	n3iwfSelf.IkeServer.RcvEventCh <- context.NewIKEDeleteRequestEvt(localSPI)
	// TODO: release pdu session and gtp info for ue
}

func encapNasMsgToEnvelope(nasPDU *ngapType.NASPDU) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU.Value)))
	nasEnv = append(nasEnv, nasPDU.Value...)
	return nasEnv
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

	var ranUe *context.N3IWFRanUe
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
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Warnf("no UE Context[RanUeNgapID:%d]", ranUeNgapID.Value)
			return
		}
	}

	if amfUeNgapID != nil {
		if ranUe.AmfUeNgapId == context.AmfUeNgapIdUnspecified {
			logger.NgapLog.Debugln("create new logical UE-associated NG-connection")
			ranUe.AmfUeNgapId = amfUeNgapID.Value
		} else {
			if ranUe.AmfUeNgapId != amfUeNgapID.Value {
				logger.NgapLog.Warnln("AMFUENGAPID unmatched")
				return
			}
		}
	}

	if oldAMF != nil {
		logger.NgapLog.Debugf("old AMF: %s", oldAMF.Value)
	}

	if indexToRFSP != nil {
		ranUe.IndexToRfsp = indexToRFSP.Value
	}

	if ueAggregateMaximumBitRate != nil {
		ranUe.Ambr = ueAggregateMaximumBitRate
	}

	if allowedNSSAI != nil {
		ranUe.AllowedNssai = allowedNSSAI
	}

	if nasPDU != nil {
		// TODO: Send NAS PDU to UE

		// Send EAP5G NAS to UE
		spi, ok := n3iwfSelf.IkeSpiLoad(ranUe.RanUeNgapId)
		if !ok {
			logger.NgapLog.Errorf("cannot get SPI from RanUeNGAPId: %d", ranUe.RanUeNgapId)
			return
		}

		if !ranUe.IsNASTCPConnEstablished {
			n3iwfSelf.IkeServer.RcvEventCh <- context.NewSendEAPNASMsgEvt(spi,
				[]byte(nasPDU.Value))
		} else {
			// Using a "NAS message envelope" to transport a NAS message
			// over the non-3GPP access between the UE and the N3IWF
			nasEnv := encapNasMsgToEnvelope(nasPDU)

			if ranUe.IsNASTCPConnEstablishedComplete {
				// Send to UE
				if n, err := ranUe.TCPConnection.Write(nasEnv); err != nil {
					logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", err)
				} else {
					logger.NgapLog.Debugln("forward NWu <- N2")
					logger.NgapLog.Debugf("wrote %d bytes", n)
				}
			} else {
				ranUe.TemporaryCachedNASMessage = nasEnv
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
	var pduSessionEstablishmentAccept *ngapType.NASPDU

	var ranUe *context.N3IWFRanUe
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
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and handle error
			// Cause: Unknown local UE NGAP ID
			return
		}
		if ranUe.AmfUeNgapId != amfUeNgapID.Value {
			// TODO: build cause and handle error
			// Cause: Inconsistent remote UE NGAP ID
			return
		}
	}

	if nasPDU != nil {
		// TODO: Send NAS to UE
		if ranUe.TCPConnection == nil {
			logger.NgapLog.Errorln("no IPSec NAS signalling SA for this UE")
			return
		}
		// Using a "NAS message envelope" to transport a NAS message
		// over the non-3GPP access between the UE and the N3IWF
		nasEnv := encapNasMsgToEnvelope(nasPDU)
		if n, err := ranUe.TCPConnection.Write(nasEnv); err != nil {
			logger.NgapLog.Errorf("send NAS to UE failed: %+v", err)
			return
		} else {
			logger.NgapLog.Debugf("wrote %d bytes", n)
		}
	}

	tempPDUSessionSetupData := ranUe.TemporaryPDUSessionSetupData
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

			pduSession, err := ranUe.CreatePDUSession(pduSessionID, snssai)
			if err != nil {
				logger.NgapLog.Errorf("create PDU Session Error: %+v", err)

				cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork,
					ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances)
				unsuccessfulTransfer, buildErr := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(*cause, nil)
				if buildErr != nil {
					logger.NgapLog.Errorf("build PDUSessionResourceSetupUnsuccessfulTransfer Error: %+v", buildErr)
				}
				ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, unsuccessfulTransfer)
				continue
			}

			success, resTransfer := handlePDUSessionResourceSetupRequestTransfer(ranUe, pduSession, transfer)
			if success {
				// Append this PDU session to unactivated PDU session list
				tempPDUSessionSetupData.UnactivatedPDUSession = append(tempPDUSessionSetupData.UnactivatedPDUSession, pduSession)
			} else {
				// Delete the pdusession store in UE conext
				delete(ranUe.PduSessionList, pduSessionID)
				ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(failedListSURes, pduSessionID, resTransfer)
			}
		}
	}

	if tempPDUSessionSetupData != nil {
		spi, ok := n3iwfSelf.IkeSpiLoad(ranUe.RanUeNgapId)
		if !ok {
			logger.NgapLog.Errorf("cannot get SPI from ranNgapID: %+v", ranUeNgapID)
			return
		}
		n3iwfSelf.IkeServer.RcvEventCh <- context.NewCreatePDUSessionEvt(spi,
			len(ranUe.PduSessionList), ranUe.TemporaryPDUSessionSetupData)

		// TS 23.501 4.12.5 Requested PDU Session Establishment via Untrusted non-3GPP Access
		// After all IPsec Child SAs are established, the N3IWF shall forward to UE via the signalling IPsec SA
		// the PDU Session Establishment Accept message
		nasEnv := encapNasMsgToEnvelope(pduSessionEstablishmentAccept)

		// Cache the pduSessionEstablishmentAccept and forward to the UE after all CREATE_CHILD_SAs finish
		ranUe.TemporaryCachedNASMessage = nasEnv
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

	var ranUe *context.N3IWFRanUe
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
		ngap_message.SendPDUSessionResourceModifyResponse(nil, nil, nil, &criticalityDiagnostics)
		return
	}

	if (amfUeNgapID != nil) && (ranUeNgapID != nil) {
		// Find UE context
		var ok bool
		ranUe, ok = n3iwfSelf.RanUePoolLoad(ranUeNgapID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", ranUeNgapID.Value)
			// TODO: build cause and send error indication
			// Cause: Unknown local UE NGAP ID
			return
		}
		if ranUe.AmfUeNgapId != amfUeNgapID.Value {
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

			if pduSession = ranUe.FindPDUSession(pduSessionID); pduSession == nil {
				logger.NgapLog.Errorf("[PDUSessionID: %d] Unknown PDU session ID", pduSessionID)

				cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID)
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

	ngap_message.SendPDUSessionResourceModifyResponse(ranUe, responseList, failedListModRes, nil)
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
		cause := ngap_message.BuildCause(ngapType.CausePresentProtocol, ngapType.CauseProtocolPresentAbstractSyntaxErrorReject)
		criticalityDiagnostics := buildCriticalityDiagnostics(nil, nil, nil, &iesCriticalityDiagnostics)
		unsuccessfulTransfer, err := ngap_message.BuildPDUSessionResourceModifyUnsuccessfulTransfer(*cause, &criticalityDiagnostics)
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

				cause := ngap_message.BuildCause(
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

	var ranUe *context.N3IWFRanUe
	n3iwfSelf := context.N3IWFSelf()

	if rANUENGAPID != nil {
		var ok bool
		ranUe, ok = n3iwfSelf.RanUePoolLoad(rANUENGAPID.Value)
		if !ok {
			logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
			return
		}
	}
	if aMFUENGAPID != nil {
		if ranUe != nil {
			if ranUe.AmfUeNgapId != aMFUENGAPID.Value {
				logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
					aMFUENGAPID.Value, ranUe.AmfUeNgapId)
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
			sess, exist := ranUe.PduSessionList[pduSessionId]
			if !exist {
				logger.NgapLog.Warnf("PDU Session Id[%d] is not exist in Ue[ranUeNgapId:%d]", pduSessionId, ranUe.RanUeNgapId)
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
			delete(ranUe.PduSessionList, pduSessionId)
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
	ranUe, ok := n3iwfSelf.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	if ranUe.AmfUeNgapId != aMFUENGAPID.Value {
		logger.NgapLog.Errorf("inconsistent remote UE NGAP ID, AMFUENGAPID: %d, RanUe.AmfUeNgapId: %d",
			aMFUENGAPID.Value, ranUe.AmfUeNgapId)
		cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, &rANUENGAPID.Value, cause, nil)
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
		delete(ranUe.PduSessionList, pduSessionId)

		// response list
		releaseItem := ngapType.PDUSessionResourceReleasedItemRelRes{
			PDUSessionID: item.PDUSessionID,
			PDUSessionResourceReleaseResponseTransfer: getPDUSessionResourceReleaseResponseTransfer(),
		}
		releaseList.List = append(releaseList.List, releaseItem)

		releaseIdList = append(releaseIdList, pduSessionId)
	}

	localSPI, ok := n3iwfSelf.IkeSpiLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("cannot get SPI from RanUeNgapID: %+v", rANUENGAPID.Value)
		return
	}

	n3iwfSelf.IkeServer.RcvEventCh <- context.NewSendChildSADeleteRequestEvt(localSPI,
		releaseIdList)

	ranUe.PduSessionReleaseList = releaseList
	// if nASPDU != nil {
	// TODO: Send NAS to UE
	// }
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
	ranUe, ok := n3iwfSelf.RanUePoolLoad(rANUENGAPID.Value)
	if !ok {
		logger.NgapLog.Errorf("unknown local UE NGAP ID. RanUENGAPID: %d", rANUENGAPID.Value)
		cause := ngap_message.BuildCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID)
		ngap_message.SendErrorIndication(amf, nil, nil, cause, nil)
		return
	}

	ranUe.RadioCapability = uERadioCapability
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
	}
	iesCriticalityDiagnostics := criticalityDiagnostics.IEsCriticalityDiagnostics
	if iesCriticalityDiagnostics == nil {
		logger.NgapLog.Warnln("IEsCriticalityDiagnostics is nil")
		return
	}
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
	case context.SendUEContextReleaseRequest:
		HandleSendUEContextReleaseRequest(ngapEvent)
	case context.SendUEContextReleaseComplete:
		HandleSendUEContextReleaseComplete(ngapEvent)
	case context.SendPDUSessionResourceReleaseResponse:
		HandleSendPDUSessionResourceReleaseRes(ngapEvent)
	case context.GetNGAPContext:
		HandleGetNGAPContext(ngapEvent)
	default:
		logger.NgapLog.Errorf("undefined NGAP event type")
		return
	}
}

func HandleGetNGAPContext(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle HandleGetNGAPContext Event")

	getNGAPContextEvt := ngapEvent.(*context.GetNGAPContextEvt)
	ranUeNgapId := getNGAPContextEvt.RanUeNgapId
	ngapCxtReqNumlist := getNGAPContextEvt.NgapCxtReqNumlist

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	var ngapCxt []any

	for _, num := range ngapCxtReqNumlist {
		switch num {
		case context.CxtTempPDUSessionSetupData:
			ngapCxt = append(ngapCxt, ranUe.TemporaryPDUSessionSetupData)
		default:
			logger.NgapLog.Errorf("receive undefined NGAP Context Request number: %d", num)
		}
	}

	spi, ok := n3iwfSelf.IkeSpiLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get spi from ngapid: %d", ranUeNgapId)
		return
	}

	n3iwfSelf.IkeServer.RcvEventCh <- context.NewGetNGAPContextRepEvt(spi,
		ngapCxtReqNumlist, ngapCxt)
}

func HandleUnmarshalEAP5GData(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle UnmarshalEAP5GData Event")

	unmarshalEAP5GDataEvt := ngapEvent.(*context.UnmarshalEAP5GDataEvt)
	spi := unmarshalEAP5GDataEvt.LocalSPI
	eapVendorData := unmarshalEAP5GDataEvt.EAPVendorData
	isInitialUE := unmarshalEAP5GDataEvt.IsInitialUE

	n3iwfSelf := context.N3IWFSelf()

	anParameters, nasPDU, err := ngap_message.UnmarshalEAP5GData(eapVendorData)
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

		selectedAMF := n3iwfSelf.AMFSelection(anParameters.GUAMI, anParameters.SelectedPLMNID)
		if selectedAMF == nil {
			n3iwfSelf.IkeServer.RcvEventCh <- context.NewSendEAP5GFailureMsgEvt(spi, context.ErrAMFSelection)
		} else {
			ranUe := n3iwfSelf.NewN3iwfRanUe()
			ranUe.AMF = selectedAMF
			if anParameters.EstablishmentCause != nil {
				ranUe.RRCEstablishmentCause = int16(anParameters.EstablishmentCause.Value)
			}

			n3iwfSelf.IkeServer.RcvEventCh <- context.NewUnmarshalEAP5GDataResponseEvt(spi,
				ranUe.RanUeNgapId, nasPDU)
		}
	} else {
		ranUeNgapId := unmarshalEAP5GDataEvt.RanUeNgapId
		ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
		if !ok {
			logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
			return
		}
		ngap_message.SendUplinkNASTransport(ranUe, nasPDU)
	}
}

func HandleSendInitialUEMessage(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendInitialUEMessage Event")

	sendInitialUEMessageEvt := ngapEvent.(*context.SendInitialUEMessageEvt)
	ranUeNgapId := sendInitialUEMessageEvt.RanUeNgapId
	ipv4Addr := sendInitialUEMessageEvt.IPv4Addr
	ipv4Port := sendInitialUEMessageEvt.IPv4Port
	nasPDU := sendInitialUEMessageEvt.NasPDU

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}
	ranUe.IPAddrv4 = ipv4Addr
	ranUe.PortNumber = int32(ipv4Port)
	ngap_message.SendInitialUEMessage(ranUe.AMF, ranUe, nasPDU)
}

func HandleSendPDUSessionResourceSetupResponse(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendPDUSessionResourceSetupResponse Event")

	sendPDUSessionResourceSetupResEvt := ngapEvent.(*context.SendPDUSessionResourceSetupResEvt)
	ranUeNgapId := sendPDUSessionResourceSetupResEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	temporaryPDUSessionSetupData := ranUe.TemporaryPDUSessionSetupData

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

				transfer, err := ngap_message.BuildPDUSessionResourceSetupUnsuccessfulTransfer(cause, nil)
				if err != nil {
					logger.NgapLog.Errorf("build PDU Session Resource Setup Unsuccessful Transfer Failed: %+v", err)
					continue
				}

				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
					ngap_message.AppendPDUSessionResourceFailedToSetupListCxtRes(
						temporaryPDUSessionSetupData.FailedListCxtRes, pduSession.Id, transfer)
				} else {
					ngap_message.AppendPDUSessionResourceFailedToSetupListSURes(
						temporaryPDUSessionSetupData.FailedListSURes, pduSession.Id, transfer)
				}
			} else {
				// Append NGAP PDU session resource setup response transfer
				transfer, err := ngap_message.BuildPDUSessionResourceSetupResponseTransfer(pduSession)
				if err != nil {
					logger.NgapLog.Errorf("build PDU session resource setup response transfer failed: %+v", err)
					return
				}
				if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
					ngap_message.AppendPDUSessionResourceSetupListCxtRes(
						temporaryPDUSessionSetupData.SetupListCxtRes, pduSession.Id, transfer)
				} else {
					ngap_message.AppendPDUSessionResourceSetupListSURes(
						temporaryPDUSessionSetupData.SetupListSURes, pduSession.Id, transfer)
				}
			}
		}

		if temporaryPDUSessionSetupData.NGAPProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup {
			ngap_message.SendInitialContextSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListCxtRes,
				temporaryPDUSessionSetupData.FailedListCxtRes, nil)
		} else {
			ngap_message.SendPDUSessionResourceSetupResponse(ranUe,
				temporaryPDUSessionSetupData.SetupListSURes,
				temporaryPDUSessionSetupData.FailedListSURes, nil)
		}
	} else {
		ngap_message.SendInitialContextSetupResponse(ranUe, nil, nil, nil)
	}
}

func HandleSendNASMsg(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendNASMsg Event")

	sendNASMsgEvt := ngapEvent.(*context.SendNASMsgEvt)
	ranUeNgapId := sendNASMsgEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	if n, ikeErr := ranUe.TCPConnection.Write(ranUe.TemporaryCachedNASMessage); ikeErr != nil {
		logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", ikeErr)
	} else {
		logger.NgapLog.Debugf("forward PDU Seesion Establishment Accept to UE. Wrote %d bytes", n)
		ranUe.TemporaryCachedNASMessage = nil
	}
}

func HandleStartTCPSignalNASMsg(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle StartTCPSignalNASMsg Event")

	startTCPSignalNASMsgEvt := ngapEvent.(*context.StartTCPSignalNASMsgEvt)
	ranUeNgapId := startTCPSignalNASMsgEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	ranUe.IsNASTCPConnEstablished = true
}

func HandleNASTCPConnEstablishedComplete(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle NASTCPConnEstablishedComplete Event")

	nasTCPConnEstablishedCompleteEvt := ngapEvent.(*context.NASTCPConnEstablishedCompleteEvt)
	ranUeNgapId := nasTCPConnEstablishedCompleteEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	ranUe.IsNASTCPConnEstablishedComplete = true

	if ranUe.TemporaryCachedNASMessage != nil {
		// Send to UE
		if n, err := ranUe.TCPConnection.Write(ranUe.TemporaryCachedNASMessage); err != nil {
			logger.NgapLog.Errorf("writing via IPSec signalling SA failed: %+v", err)
		} else {
			logger.NgapLog.Debugln("forward NWu <- N2")
			logger.NgapLog.Debugf("wrote %d bytes", n)
		}
		ranUe.TemporaryCachedNASMessage = nil
	}
}

func HandleSendUEContextReleaseRequest(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendUEContextReleaseRequest Event")

	sendUEContextReleaseReqEvt := ngapEvent.(*context.SendUEContextReleaseRequestEvt)

	ranUeNgapId := sendUEContextReleaseReqEvt.RanUeNgapId
	errMsg := sendUEContextReleaseReqEvt.ErrMsg

	var cause *ngapType.Cause
	switch errMsg {
	case context.ErrRadioConnWithUeLost:
		cause = ngap_message.BuildCause(ngapType.CausePresentRadioNetwork,
			ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost)
	case context.ErrNil:
	default:
		logger.NgapLog.Errorf("undefined event error string: %+s", errMsg.Error())
		return
	}

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	ngap_message.SendUEContextReleaseRequest(ranUe, *cause)
}

func HandleSendUEContextReleaseComplete(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendUEContextReleaseComplete Event")

	sendUEContextReleaseCompleteEvt := ngapEvent.(*context.SendUEContextReleaseCompleteEvt)
	ranUeNgapId := sendUEContextReleaseCompleteEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	if err := ranUe.Remove(); err != nil {
		logger.NgapLog.Errorf("delete RanUe Context error: %+v", err)
	}
	ngap_message.SendUEContextReleaseComplete(ranUe, nil)
}

func HandleSendPDUSessionResourceReleaseRes(ngapEvent context.NgapEvt) {
	logger.NgapLog.Debugln("handle SendPDUSessionResourceReleaseResponse Event")

	sendPDUSessionResourceReleaseResEvt := ngapEvent.(*context.SendPDUSessionResourceReleaseResEvt)
	ranUeNgapId := sendPDUSessionResourceReleaseResEvt.RanUeNgapId

	n3iwfSelf := context.N3IWFSelf()
	ranUe, ok := n3iwfSelf.RanUePoolLoad(ranUeNgapId)
	if !ok {
		logger.NgapLog.Errorf("cannot get RanUE from ranUeNgapId: %d", ranUeNgapId)
		return
	}

	ngap_message.SendPDUSessionResourceReleaseResponse(ranUe, ranUe.PduSessionReleaseList, nil)
}
