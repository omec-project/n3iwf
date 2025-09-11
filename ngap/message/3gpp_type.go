// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"encoding/binary"
	"errors"

	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/aper"
	"github.com/omec-project/ngap/ngapType"
)

// Used in AN-Parameter field for IE types
const (
	ANParametersTypeGUAMI              = 1
	ANParametersTypeSelectedPLMNID     = 2
	ANParametersTypeRequestedNSSAI     = 3
	ANParametersTypeEstablishmentCause = 4
)

// Used for checking if AN-Parameter length field is legal
const (
	ANParametersLenGUAMI    = 6
	ANParametersLenPLMNID   = 3
	ANParametersLenEstCause = 1
)

// Used in IE Establishment Cause field for cause types
const (
	EstablishmentCauseEmergency          = 0
	EstablishmentCauseHighPriorityAccess = 1
	EstablishmentCauseMO_Signalling      = 3
	EstablishmentCauseMO_Data            = 4
	EstablishmentCauseMPS_PriorityAccess = 8
	EstablishmentCauseMCS_PriorityAccess = 9
)

const MaxNumOfPDUSessions int = 256

// Access Network Parameters
type ANParameters struct {
	GUAMI              *ngapType.GUAMI
	SelectedPLMNID     *ngapType.PLMNIdentity
	RequestedNSSAI     *ngapType.AllowedNSSAI
	EstablishmentCause *ngapType.RRCEstablishmentCause
}

func UnmarshalEAP5GData(codedData []byte) (anParameters *ANParameters, nasPDU []byte, err error) {
	if len(codedData) < 2 {
		return nil, nil, errors.New("no data to decode")
	}
	logger.NgapLog.Debugln("===== Unmarshal EAP5G Data (Ref: TS24.502 Fig. 9.3.2.2.2-1) =====")

	codedData = codedData[2:]

	// [TS 24.502 f30] 9.3.2.2.2.3
	// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
	// Therefore, IEI of AN-parameter is not needed to be included.
	// anParameter = AN-parameter Type | AN-parameter Length | Value part of IE

	if len(codedData) < 2 {
		logger.NgapLog.Errorln("no AN-Parameter type or length specified")
		return nil, nil, errors.New("error formatting")
	}
	// Length of the AN-Parameter field
	anParameterLength := binary.BigEndian.Uint16(codedData[:2])
	logger.NgapLog.Debugf("AN-parameters length: %d", anParameterLength)

	if anParameterLength != 0 {
		anParameterField := codedData[2:]

		// Bound checking
		if len(anParameterField) < int(anParameterLength) {
			logger.NgapLog.Errorln("packet contained error length of value")
			return nil, nil, errors.New("error formatting")
		}
		anParameterField = anParameterField[:anParameterLength]

		logger.NgapLog.Debugf("parsing AN-parameters: %+v", anParameterField)

		anParameters = new(ANParameters)

		// Parse AN-Parameters
		for len(anParameterField) >= 2 {
			parameterType := anParameterField[0]
			// The AN-parameter length field indicates the length of the AN-parameter value field.
			parameterLength := anParameterField[1]

			switch parameterType {
			case ANParametersTypeGUAMI:
				logger.NgapLog.Debugf("-> Parameter type: GUAMI")
				if parameterLength != 0 {
					parameterValue := anParameterField[2:]

					if len(parameterValue) < int(parameterLength) {
						return nil, nil, errors.New("error formatting")
					}
					parameterValue = parameterValue[:parameterLength]

					if len(parameterValue) != ANParametersLenGUAMI {
						return nil, nil, errors.New("unmatched GUAMI length")
					}

					guamiField := make([]byte, 1)
					guamiField = append(guamiField, parameterValue...)
					// Decode GUAMI using aper
					ngapGUAMI := new(ngapType.GUAMI)
					err := aper.UnmarshalWithParams(guamiField, ngapGUAMI, "valueExt")
					if err != nil {
						logger.NgapLog.Errorf("APER unmarshal with parameter failed: %+v", err)
						return nil, nil, errors.New("unmarshal failed when decoding GUAMI")
					}
					anParameters.GUAMI = ngapGUAMI
					logger.NgapLog.Debugf("Unmarshal GUAMI: % x", guamiField)
					logger.NgapLog.Debugf("\tGUAMI: PLMNIdentity[% x], "+
						"AMFRegionID[% x], AMFSetID[% x], AMFPointer[% x]",
						anParameters.GUAMI.PLMNIdentity, anParameters.GUAMI.AMFRegionID,
						anParameters.GUAMI.AMFSetID, anParameters.GUAMI.AMFPointer)
				} else {
					logger.NgapLog.Warnln("AN-Parameter GUAMI field is empty")
				}
			case ANParametersTypeSelectedPLMNID:
				logger.NgapLog.Debugln("-> Parameter type: ANParametersTypeSelectedPLMNID")
				if parameterLength != 0 {
					parameterValue := anParameterField[2:]

					if len(parameterValue) < int(parameterLength) {
						return nil, nil, errors.New("error formatting")
					}
					parameterValue = parameterValue[:parameterLength]

					if len(parameterValue) != ANParametersLenPLMNID {
						return nil, nil, errors.New("unmatched PLMN ID length")
					}

					plmnField := make([]byte, 1)
					plmnField = append(plmnField, parameterValue...)
					// Decode PLMN using aper
					ngapPLMN := new(ngapType.PLMNIdentity)
					err := aper.UnmarshalWithParams(plmnField, ngapPLMN, "valueExt")
					if err != nil {
						logger.NgapLog.Errorf("APER unmarshal with parameter failed: %v", err)
						return nil, nil, errors.New("unmarshal failed when decoding PLMN")
					}
					anParameters.SelectedPLMNID = ngapPLMN
					logger.NgapLog.Debugf("Unmarshal SelectedPLMNID: % x", plmnField)
					logger.NgapLog.Debugf("\tSelectedPLMNID: % x", anParameters.SelectedPLMNID.Value)
				} else {
					logger.NgapLog.Warnln("AN-Parameter PLMN field empty")
				}
			case ANParametersTypeRequestedNSSAI:
				logger.NgapLog.Debugln("-> Parameter type: ANParametersTypeRequestedNSSAI")
				if parameterLength != 0 {
					parameterValue := anParameterField[2:]

					if len(parameterValue) < int(parameterLength) {
						return nil, nil, errors.New("error formatting")
					}
					parameterValue = parameterValue[:parameterLength]

					ngapNSSAI := new(ngapType.AllowedNSSAI)

					// [TS 24501 f30] 9.11.2.8 S-NSSAI
					// s-nssai(LV) consists of
					// len(1 byte) | SST(1) | SD(3,opt) | Mapped HPLMN SST (1,opt) | Mapped HPLMN SD (3,opt)
					// The length of minimum s-nssai comprised of a length and a SST is 2 bytes.

					for len(parameterValue) >= 2 {
						snssaiLength := parameterValue[0]
						snssaiValue := parameterValue[1:]

						if len(snssaiValue) < int(snssaiLength) {
							return nil, nil, errors.New("error formatting")
						}
						snssaiValue = snssaiValue[:snssaiLength]

						ngapSNSSAIItem := ngapType.AllowedNSSAIItem{}

						switch len(snssaiValue) {
						case 1:
							ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
								SST: ngapType.SST{
									Value: []byte{snssaiValue[0]},
								},
							}
						case 4:
							ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
								SST: ngapType.SST{
									Value: []byte{snssaiValue[0]},
								},
								SD: &ngapType.SD{
									Value: []byte{snssaiValue[1], snssaiValue[2], snssaiValue[3]},
								},
							}
						default:
							logger.NgapLog.Errorln("SNSSAI length error")
							return nil, nil, errors.New("error formatting")
						}

						ngapNSSAI.List = append(ngapNSSAI.List, ngapSNSSAIItem)
						logger.NgapLog.Debugf("Unmarshal SNSSAI: % x", parameterValue[:1+snssaiLength])
						logger.NgapLog.Debugf("\t\t\tSST: % x", ngapSNSSAIItem.SNSSAI.SST.Value)
						sd := ngapSNSSAIItem.SNSSAI.SD
						if sd == nil {
							logger.NgapLog.Debugf("\t\t\tSD: nil")
						} else {
							logger.NgapLog.Debugf("\t\t\tSD: % x", sd.Value)
						}

						// shift parameterValue for parsing next s-nssai
						parameterValue = parameterValue[1+snssaiLength:]
					}
					anParameters.RequestedNSSAI = ngapNSSAI
				} else {
					logger.NgapLog.Warnln("AN-Parameter value for NSSAI is empty")
				}
			case ANParametersTypeEstablishmentCause:
				logger.NgapLog.Debugln("-> Parameter type: ANParametersTypeEstablishmentCause")
				if parameterLength != 0 {
					parameterValue := anParameterField[2:]

					if len(parameterValue) < int(parameterLength) {
						return nil, nil, errors.New("error formatting")
					}
					parameterValue = parameterValue[:parameterLength]

					if len(parameterValue) != ANParametersLenEstCause {
						return nil, nil, errors.New("unmatched Establishment Cause length")
					}
					logger.NgapLog.Debugf("Unmarshal ANParametersTypeEstablishmentCause: % x", parameterValue)

					establishmentCause := parameterValue[0] & 0x0f
					switch establishmentCause {
					case EstablishmentCauseEmergency:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: Emergency")
					case EstablishmentCauseHighPriorityAccess:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: High Priority Access")
					case EstablishmentCauseMO_Signalling:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: MO Signalling")
					case EstablishmentCauseMO_Data:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: MO Data")
					case EstablishmentCauseMPS_PriorityAccess:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: MPS Priority Access")
					case EstablishmentCauseMCS_PriorityAccess:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: MCS Priority Access")
					default:
						logger.NgapLog.Debugln("AN-Parameter establishment cause: Unknown. Treat as mo-Data")
						establishmentCause = EstablishmentCauseMO_Data
					}

					ngapEstablishmentCause := new(ngapType.RRCEstablishmentCause)
					ngapEstablishmentCause.Value = aper.Enumerated(establishmentCause)

					anParameters.EstablishmentCause = ngapEstablishmentCause
				} else {
					logger.NgapLog.Warnln("AN-Parameter establishment cause field empty")
				}
			default:
				logger.NgapLog.Warnln("ignoring unsupported AN-Parameter")
			}

			// shift anParameterField
			anParameterField = anParameterField[2+parameterLength:]
		}
	}

	// shift codedData
	codedData = codedData[2+anParameterLength:]

	if len(codedData) < 2 {
		logger.NgapLog.Errorln("no NASPDU length specified")
		return nil, nil, errors.New("error formatting")
	}

	// Length of the NASPDU field
	nasPDULength := binary.BigEndian.Uint16(codedData[:2])
	logger.NgapLog.Debugf("nasPDULength: %d", nasPDULength)

	if nasPDULength == 0 {
		logger.NgapLog.Errorln("no NASPDU length specified")
		return nil, nil, errors.New("error formatting")
	}
	nasPDUField := codedData[2:]

	// Bound checking
	if len(nasPDUField) < int(nasPDULength) {
		return nil, nil, errors.New("error formatting")
	}
	nasPDUField = nasPDUField[:nasPDULength]
	logger.NgapLog.Debugf("nasPDUField: %v", nasPDUField)

	nasPDU = append(nasPDU, nasPDUField...)

	return anParameters, nasPDU, nil
}
