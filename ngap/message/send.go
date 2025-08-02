// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"runtime/debug"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/ngapType"
)

func SendToAmf(amf *context.N3IWFAMF, pkt []byte) {
	if amf == nil {
		logger.NgapLog.Errorln("AMF Context is nil ")
	} else {
		if n, err := amf.SCTPConn.Write(pkt); err != nil {
			logger.NgapLog.Errorf("write to SCTP socket failed: %+v", err)
		} else {
			logger.NgapLog.Debugf("wrote %d bytes", n)
		}
	}
}

func SendNGSetupRequest(conn *sctp.SCTPConn) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NgapLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	logger.NgapLog.Infoln("send NG Setup Request")

	sctpAddr := conn.RemoteAddr().String()

	if available, _ := context.N3IWFSelf().AMFReInitAvailableListLoad(sctpAddr); !available {
		logger.NgapLog.Warnf("wait at least for the indicated time before reinitiating toward same AMF[%s]", sctpAddr)
		return
	}
	pkt, err := BuildNGSetupRequest()
	if err != nil {
		logger.NgapLog.Errorf("build NGSetup Request failed: %+v", err)
		return
	}

	if n, err := conn.Write(pkt); err != nil {
		logger.NgapLog.Errorf("write to SCTP socket failed: %+v", err)
	} else {
		logger.NgapLog.Debugf("wrote %d bytes", n)
	}
}

// partOfNGInterface: if reset type is "reset all", set it to nil TS 38.413 9.2.6.11
func SendNGReset(
	amf *context.N3IWFAMF,
	cause ngapType.Cause,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
) {
	logger.NgapLog.Infoln("send NG Reset")

	pkt, err := BuildNGReset(cause, partOfNGInterface)
	if err != nil {
		logger.NgapLog.Errorf("build NGReset failed: %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendNGResetAcknowledge(
	amf *context.N3IWFAMF,
	partOfNGInterface *ngapType.UEAssociatedLogicalNGConnectionList,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send NG Reset Acknowledge")

	if partOfNGInterface != nil && len(partOfNGInterface.List) == 0 {
		logger.NgapLog.Errorln("length of partOfNGInterface is 0")
		return
	}

	pkt, err := BuildNGResetAcknowledge(partOfNGInterface, diagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build NGReset Acknowledge failed: %s", err.Error())
		return
	}

	SendToAmf(amf, pkt)
}

func SendInitialContextSetupResponse(
	ranUe *context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceSetupListCxtRes,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send Initial Context Setup Response")

	if responseList != nil && len(responseList.List) > MaxNumOfPDUSessions {
		logger.NgapLog.Errorln("pdu list out of range")
		return
	}

	if failedList != nil && len(failedList.List) > MaxNumOfPDUSessions {
		logger.NgapLog.Errorln("pdu list out of range")
		return
	}

	pkt, err := BuildInitialContextSetupResponse(ranUe, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build Initial Context Setup Response failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendInitialContextSetupFailure(
	ranUe *context.N3IWFRanUe,
	cause ngapType.Cause,
	failedList *ngapType.PDUSessionResourceFailedToSetupListCxtFail,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send Initial Context Setup Failure")

	if failedList != nil && len(failedList.List) > MaxNumOfPDUSessions {
		logger.NgapLog.Errorln("pdu list out of range")
		return
	}

	pkt, err := BuildInitialContextSetupFailure(ranUe, cause, failedList, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build Initial Context Setup Failure failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextModificationResponse(
	ranUe *context.N3IWFRanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send UE Context Modification Response")

	pkt, err := BuildUEContextModificationResponse(ranUe, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build UE Context Modification Response failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextModificationFailure(
	ranUe *context.N3IWFRanUe,
	cause ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send UE Context Modification Failure")

	pkt, err := BuildUEContextModificationFailure(ranUe, cause, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build UE Context Modification Failure failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextReleaseComplete(
	ranUe *context.N3IWFRanUe,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send UE Context Release Complete")

	pkt, err := BuildUEContextReleaseComplete(ranUe, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build UE Context Release Complete failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUEContextReleaseRequest(
	ranUe *context.N3IWFRanUe, cause ngapType.Cause,
) {
	logger.NgapLog.Infoln("send UE Context Release Request")

	pkt, err := BuildUEContextReleaseRequest(ranUe, cause)
	if err != nil {
		logger.NgapLog.Errorf("build UE Context Release Request failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendInitialUEMessage(amf *context.N3IWFAMF,
	ranUe *context.N3IWFRanUe, nasPdu []byte,
) {
	logger.NgapLog.Infoln("send Initial UE Message")
	// Attach To AMF

	pkt, err := BuildInitialUEMessage(ranUe, nasPdu, nil)
	if err != nil {
		logger.NgapLog.Errorf("build Initial UE Message failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendUplinkNASTransport(
	ranUe *context.N3IWFRanUe,
	nasPdu []byte,
) {
	logger.NgapLog.Infoln("send Uplink NAS Transport")

	if len(nasPdu) == 0 {
		logger.NgapLog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildUplinkNASTransport(ranUe, nasPdu)
	if err != nil {
		logger.NgapLog.Errorf("build Uplink NAS Transport failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendNASNonDeliveryIndication(
	ranUe *context.N3IWFRanUe,
	nasPdu []byte,
	cause ngapType.Cause,
) {
	logger.NgapLog.Infoln("send NAS NonDelivery Indication")

	if len(nasPdu) == 0 {
		logger.NgapLog.Errorln("NAS Pdu is nil")
		return
	}

	pkt, err := BuildNASNonDeliveryIndication(ranUe, nasPdu, cause)
	if err != nil {
		logger.NgapLog.Errorf("build Uplink NAS Transport failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendRerouteNASRequest() {
	logger.NgapLog.Infoln("send Reroute NAS Request")
}

func SendPDUSessionResourceSetupResponse(
	ranUe *context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceSetupListSURes,
	failedListSURes *ngapType.PDUSessionResourceFailedToSetupListSURes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send PDU Session Resource Setup Response")

	if ranUe == nil {
		logger.NgapLog.Errorln("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceSetupResponse(ranUe, responseList, failedListSURes, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build PDU Session Resource Setup Response failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceModifyResponse(
	ranUe *context.N3IWFRanUe,
	responseList *ngapType.PDUSessionResourceModifyListModRes,
	failedList *ngapType.PDUSessionResourceFailedToModifyListModRes,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send PDU Session Resource Modify Response")

	if ranUe == nil && criticalityDiagnostics == nil {
		logger.NgapLog.Errorln("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyResponse(ranUe, responseList, failedList, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build PDU Session Resource Modify Response failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceModifyIndication(
	ranUe *context.N3IWFRanUe,
	modifyList []ngapType.PDUSessionResourceModifyItemModInd,
) {
	logger.NgapLog.Infoln("send PDU Session Resource Modify Indication")

	if ranUe == nil {
		logger.NgapLog.Errorln("UE context is nil, this information is mandatory")
		return
	}
	if modifyList == nil {
		logger.NgapLog.Errorln("PDU Session Resource Modify Indication List is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceModifyIndication(ranUe, modifyList)
	if err != nil {
		logger.NgapLog.Errorf("build PDU Session Resource Modify Indication failed : %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceNotify(
	ranUe *context.N3IWFRanUe,
	notiList *ngapType.PDUSessionResourceNotifyList,
	relList *ngapType.PDUSessionResourceReleasedListNot,
) {
	logger.NgapLog.Infoln("send PDU Session Resource Notify")

	if ranUe == nil {
		logger.NgapLog.Errorln("UE context is nil, this information is mandatory")
		return
	}

	pkt, err := BuildPDUSessionResourceNotify(ranUe, notiList, relList)
	if err != nil {
		logger.NgapLog.Errorf("build PDUSession Resource Notify failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendPDUSessionResourceReleaseResponse(
	ranUe *context.N3IWFRanUe,
	relList ngapType.PDUSessionResourceReleasedListRelRes,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send PDU Session Resource Release Response")

	if ranUe == nil {
		logger.NgapLog.Errorln("UE context is nil, this information is mandatory")
		return
	}
	if len(relList.List) == 0 {
		logger.NgapLog.Errorln("PDUSessionResourceReleasedListRelRes is nil. This message shall contain at least one Item")
		return
	}

	pkt, err := BuildPDUSessionResourceReleaseResponse(ranUe, relList, diagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build PDU Session Resource Release Response failed: %+v", err)
		return
	}

	SendToAmf(ranUe.AMF, pkt)
}

func SendErrorIndication(
	amf *context.N3IWFAMF,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		logger.NgapLog.Errorln("both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build Error Indication failed: %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendErrorIndicationWithSctpConn(
	sctpConn *sctp.SCTPConn,
	amfUENGAPID *int64,
	ranUENGAPID *int64,
	cause *ngapType.Cause,
	criticalityDiagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send Error Indication")

	if (cause == nil) && (criticalityDiagnostics == nil) {
		logger.NgapLog.Errorln("both cause and criticality is nil. This message shall contain at least one of them.")
		return
	}

	pkt, err := BuildErrorIndication(amfUENGAPID, ranUENGAPID, cause, criticalityDiagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build Error Indication failed: %+v", err)
		return
	}

	if n, err := sctpConn.Write(pkt); err != nil {
		logger.NgapLog.Errorf("write to SCTP socket failed: %+v", err)
	} else {
		logger.NgapLog.Debugf("wrote %d bytes", n)
	}
}

func SendUERadioCapabilityInfoIndication() {
	logger.NgapLog.Infoln("send UE Radio Capability Info Indication")
}

func SendUERadioCapabilityCheckResponse(
	amf *context.N3IWFAMF,
	ranUe *context.N3IWFRanUe,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send UE Radio Capability Check Response")

	pkt, err := BuildUERadioCapabilityCheckResponse(ranUe, diagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build UERadio Capability Check Response failed: %+v", err)
		return
	}
	SendToAmf(ranUe.AMF, pkt)
}

func SendAMFConfigurationUpdateAcknowledge(
	amf *context.N3IWFAMF,
	setupList *ngapType.AMFTNLAssociationSetupList,
	failList *ngapType.TNLAssociationList,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send AMF Configuration Update Acknowledge")

	pkt, err := BuildAMFConfigurationUpdateAcknowledge(setupList, failList, diagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build AMF Configuration Update Acknowledge failed: %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendAMFConfigurationUpdateFailure(
	amf *context.N3IWFAMF,
	ngCause ngapType.Cause,
	time *ngapType.TimeToWait,
	diagnostics *ngapType.CriticalityDiagnostics,
) {
	logger.NgapLog.Infoln("send AMF Configuration Update Failure")
	pkt, err := BuildAMFConfigurationUpdateFailure(ngCause, time, diagnostics)
	if err != nil {
		logger.NgapLog.Errorf("build AMF Configuration Update Failure failed: %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendRANConfigurationUpdate(amf *context.N3IWFAMF) {
	logger.NgapLog.Infoln("send RAN Configuration Update")

	if available, _ := context.N3IWFSelf().AMFReInitAvailableListLoad(amf.SCTPAddr); !available {
		logger.NgapLog.Warnf(
			"wait at least for the indicated time before reinitiating toward same AMF[%s]", amf.SCTPAddr)
		return
	}

	pkt, err := BuildRANConfigurationUpdate()
	if err != nil {
		logger.NgapLog.Errorf("build AMF Configuration Update Failure failed: %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func SendUplinkRANConfigurationTransfer() {
	logger.NgapLog.Infoln("send Uplink RAN Configuration Transfer")
}

func SendUplinkRANStatusTransfer() {
	logger.NgapLog.Infoln("send Uplink RAN Status Transfer")
}

func SendLocationReportingFailureIndication() {
	logger.NgapLog.Infoln("send Location Reporting Failure Indication")
}

func SendLocationReport() {
	logger.NgapLog.Infoln("send Location Report")
}

func SendRRCInactiveTransitionReport() {
	logger.NgapLog.Infoln("send RRC Inactive Transition Report")
}
