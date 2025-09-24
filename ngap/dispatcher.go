// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package ngap

import (
	"github.com/ishidawataru/sctp"
	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/ngap/handler"
	"github.com/omec-project/n3iwf/util"
	"github.com/omec-project/ngap"
	"github.com/omec-project/ngap/ngapType"
)

func Dispatch(conn *sctp.SCTPConn, msg []byte) {
	defer util.RecoverWithLog(logger.NgapLog)

	// AMF SCTP address
	sctpAddr := conn.RemoteAddr().String()
	// AMF context
	amf, _ := context.N3IWFSelf().AMFPoolLoad(sctpAddr)
	// Decode
	pdu, err := ngap.Decoder(msg)
	if err != nil {
		logger.NgapLog.Errorf("NGAP decode error: %+v", err)
		return
	}

	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		handleInitiatingMessage(amf, pdu)
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		handleSuccessfulOutcome(sctpAddr, conn, amf, pdu)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		handleUnsuccessfulOutcome(sctpAddr, conn, amf, pdu)
	}
}

// handleInitiatingMessage processes NGAP Initiating Messages
func handleInitiatingMessage(amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	initiatingMessage := pdu.InitiatingMessage
	if initiatingMessage == nil {
		logger.NgapLog.Errorln("initiating message is nil")
		return
	}

	switch initiatingMessage.ProcedureCode.Value {
	case ngapType.ProcedureCodeNGReset:
		handler.HandleNGReset(amf, pdu)
	case ngapType.ProcedureCodeInitialContextSetup:
		handler.HandleInitialContextSetupRequest(amf, pdu)
	case ngapType.ProcedureCodeUEContextModification:
		handler.HandleUEContextModificationRequest(amf, pdu)
	case ngapType.ProcedureCodeUEContextRelease:
		handler.HandleUEContextReleaseCommand(amf, pdu)
	case ngapType.ProcedureCodeDownlinkNASTransport:
		handler.HandleDownlinkNASTransport(amf, pdu)
	case ngapType.ProcedureCodePDUSessionResourceSetup:
		handler.HandlePDUSessionResourceSetupRequest(amf, pdu)
	case ngapType.ProcedureCodePDUSessionResourceModify:
		handler.HandlePDUSessionResourceModifyRequest(amf, pdu)
	case ngapType.ProcedureCodePDUSessionResourceRelease:
		handler.HandlePDUSessionResourceReleaseCommand(amf, pdu)
	case ngapType.ProcedureCodeErrorIndication:
		handler.HandleErrorIndication(amf, pdu)
	case ngapType.ProcedureCodeUERadioCapabilityCheck:
		handler.HandleUERadioCapabilityCheckRequest(amf, pdu)
	case ngapType.ProcedureCodeAMFConfigurationUpdate:
		handler.HandleAMFConfigurationUpdate(amf, pdu)
	case ngapType.ProcedureCodeDownlinkRANConfigurationTransfer:
		handler.HandleDownlinkRANConfigurationTransfer(pdu)
	case ngapType.ProcedureCodeDownlinkRANStatusTransfer:
		handler.HandleDownlinkRANStatusTransfer(pdu)
	case ngapType.ProcedureCodeAMFStatusIndication:
		handler.HandleAMFStatusIndication(pdu)
	case ngapType.ProcedureCodeLocationReportingControl:
		handler.HandleLocationReportingControl(pdu)
	case ngapType.ProcedureCodeUETNLABindingRelease:
		handler.HandleUETNLAReleaseRequest(pdu)
	case ngapType.ProcedureCodeOverloadStart:
		handler.HandleOverloadStart(amf, pdu)
	case ngapType.ProcedureCodeOverloadStop:
		handler.HandleOverloadStop(amf, pdu)
	default:
		logger.NgapLog.Warnf("not implemented NGAP message (initiatingMessage), procedureCode:%d]", initiatingMessage.ProcedureCode.Value)
	}
}

// handleSuccessfulOutcome processes NGAP Successful Outcome Messages
func handleSuccessfulOutcome(sctpAddr string, conn *sctp.SCTPConn, amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	successfulOutcome := pdu.SuccessfulOutcome
	if successfulOutcome == nil {
		logger.NgapLog.Errorln("successful Outcome is nil")
		return
	}

	switch successfulOutcome.ProcedureCode.Value {
	case ngapType.ProcedureCodeNGSetup:
		handler.HandleNGSetupResponse(sctpAddr, conn, pdu)
	case ngapType.ProcedureCodeNGReset:
		handler.HandleNGResetAcknowledge(amf, pdu)
	case ngapType.ProcedureCodePDUSessionResourceModifyIndication:
		handler.HandlePDUSessionResourceModifyConfirm(amf, pdu)
	case ngapType.ProcedureCodeRANConfigurationUpdate:
		handler.HandleRANConfigurationUpdateAcknowledge(amf, pdu)
	default:
		logger.NgapLog.Warnf("not implemented NGAP message (successfulOutcome), procedureCode:%d]", successfulOutcome.ProcedureCode.Value)
	}
}

// handleUnsuccessfulOutcome processes NGAP Unsuccessful Outcome Messages
func handleUnsuccessfulOutcome(sctpAddr string, conn *sctp.SCTPConn, amf *context.N3IWFAMF, pdu *ngapType.NGAPPDU) {
	unsuccessfulOutcome := pdu.UnsuccessfulOutcome
	if unsuccessfulOutcome == nil {
		logger.NgapLog.Errorln("unsuccessful Outcome is nil")
		return
	}

	switch unsuccessfulOutcome.ProcedureCode.Value {
	case ngapType.ProcedureCodeNGSetup:
		handler.HandleNGSetupFailure(sctpAddr, conn, pdu)
	case ngapType.ProcedureCodeRANConfigurationUpdate:
		handler.HandleRANConfigurationUpdateFailure(amf, pdu)
	default:
		logger.NgapLog.Warnf("not implemented NGAP message (unsuccessfulOutcome), procedureCode:%d]", unsuccessfulOutcome.ProcedureCode.Value)
	}
}
