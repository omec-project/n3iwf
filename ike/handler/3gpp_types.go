// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/binary"
	"errors"

	"github.com/omec-project/aper"
	"github.com/omec-project/n3iwf/ike/message"
	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/ngap/ngapType"
)

// 3GPP specified EAP-5G

// Access Network Parameters
type ANParameters struct {
	GUAMI              *ngapType.GUAMI
	SelectedPLMNID     *ngapType.PLMNIdentity
	RequestedNSSAI     *ngapType.AllowedNSSAI
	EstablishmentCause *ngapType.RRCEstablishmentCause
}

func UnmarshalEAP5GData(codedData []byte) (eap5GMessageID uint8, anParameters *ANParameters, nasPDU []byte, err error) {
	if len(codedData) >= 2 {
		eap5GMessageID = codedData[0]

		if eap5GMessageID == message.EAP5GType5GStop {
			return eap5GMessageID, anParameters, nasPDU, errors.New("received EAP5GType5GStop")
		}

		codedData = codedData[2:]

		if len(codedData) >= 2 {
			// Length of the AN-Parameter field
			anParameterLength := binary.BigEndian.Uint16(codedData[:2])

			if anParameterLength != 0 {
				anParameterField := codedData[2:]

				// Bound checking
				if len(anParameterField) < int(anParameterLength) {
					logger.IKELog.Errorln("packet contained error length of value")
					return 0, nil, nil, errors.New("error formatting")
				} else {
					anParameterField = anParameterField[:anParameterLength]
				}

				anParameters = new(ANParameters)

				// Parse AN-Parameters
				for len(anParameterField) >= 2 {
					parameterType := anParameterField[0]
					// The AN-parameter length field indicates the length of the AN-parameter value field.
					parameterLength := anParameterField[1]

					switch parameterType {
					case message.ANParametersTypeGUAMI:
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != 7 {
								return 0, nil, nil, errors.New("unmatched GUAMI length")
							}

							guamiField := make([]byte, 1)
							guamiField = append(guamiField, parameterValue[1:]...)
							// Decode GUAMI using aper
							ngapGUAMI := new(ngapType.GUAMI)
							err := aper.UnmarshalWithParams(guamiField, ngapGUAMI, "valueExt")
							if err != nil {
								logger.IKELog.Errorf("APER unmarshal with parameter failed: %+v", err)
								return 0, nil, nil, errors.New("unmarshal failed when decoding GUAMI")
							}
							anParameters.GUAMI = ngapGUAMI
						} else {
							logger.IKELog.Warnln("AN-Parameter GUAMI field empty")
						}
					case message.ANParametersTypeSelectedPLMNID:
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != 5 {
								return 0, nil, nil, errors.New("unmatched PLMN ID length")
							}

							plmnField := make([]byte, 1)
							plmnField = append(plmnField, parameterValue[2:]...)
							// Decode PLMN using aper
							ngapPLMN := new(ngapType.PLMNIdentity)
							err := aper.UnmarshalWithParams(plmnField, ngapPLMN, "valueExt")
							if err != nil {
								logger.IKELog.Errorf("APER unmarshal with parameter failed: %v", err)
								return 0, nil, nil, errors.New("unmarshal failed when decoding PLMN")
							}
							anParameters.SelectedPLMNID = ngapPLMN
						} else {
							logger.IKELog.Warnln("AN-Parameter PLMN field empty")
						}
					case message.ANParametersTypeRequestedNSSAI:
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) >= 2 {
								nssaiLength := parameterValue[1]

								if nssaiLength != 0 {
									nssaiValue := parameterValue[2:]

									if len(nssaiValue) < int(nssaiLength) {
										return 0, nil, nil, errors.New("error formatting")
									} else {
										nssaiValue = nssaiValue[:nssaiLength]
									}

									ngapNSSAI := new(ngapType.AllowedNSSAI)

									for len(nssaiValue) >= 2 {
										snssaiLength := nssaiValue[1]

										if snssaiLength != 0 {
											snssaiValue := nssaiValue[2:]

											if len(snssaiValue) < int(snssaiLength) {
												return 0, nil, nil, errors.New("error formatting")
											} else {
												snssaiValue = snssaiValue[:snssaiLength]
											}

											ngapSNSSAIItem := ngapType.AllowedNSSAIItem{}

											if len(snssaiValue) == 1 {
												ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
													SST: ngapType.SST{
														Value: []byte{snssaiValue[0]},
													},
												}
											} else if len(snssaiValue) == 4 {
												ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
													SST: ngapType.SST{
														Value: []byte{snssaiValue[0]},
													},
													SD: &ngapType.SD{
														Value: []byte{snssaiValue[1], snssaiValue[2], snssaiValue[3]},
													},
												}
											} else {
												logger.IKELog.Errorln("SNSSAI length error")
												return 0, nil, nil, errors.New("error formatting")
											}

											ngapNSSAI.List = append(ngapNSSAI.List, ngapSNSSAIItem)
										} else {
											logger.IKELog.Errorln("empty SNSSAI value")
											return 0, nil, nil, errors.New("error formatting")
										}

										// shift nssaiValue
										nssaiValue = nssaiValue[2+snssaiLength:]
									}

									anParameters.RequestedNSSAI = ngapNSSAI
								} else {
									logger.IKELog.Errorln("empty NSSAI value")
									return 0, nil, nil, errors.New("error formatting")
								}
							} else {
								logger.IKELog.Errorln("no NSSAI type or length specified")
								return 0, nil, nil, errors.New("error formatting")
							}
						} else {
							logger.IKELog.Warnln("AN-Parameter value for NSSAI empty")
						}
					case message.ANParametersTypeEstablishmentCause:
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != 2 {
								return 0, nil, nil, errors.New("unmatched Establishment Cause length")
							}

							establishmentCause := parameterValue[1] & 0x0f
							switch establishmentCause {
							case message.EstablishmentCauseEmergency:
								logger.IKELog.Debugln("AN-Parameter establishment cause: Emergency")
							case message.EstablishmentCauseHighPriorityAccess:
								logger.IKELog.Debugln("AN-Parameter establishment cause: High Priority Access")
							case message.EstablishmentCauseMO_Signalling:
								logger.IKELog.Debugln("AN-Parameter establishment cause: MO Signalling")
							case message.EstablishmentCauseMO_Data:
								logger.IKELog.Debugln("AN-Parameter establishment cause: MO Data")
							case message.EstablishmentCauseMPS_PriorityAccess:
								logger.IKELog.Debugln("AN-Parameter establishment cause: MPS Priority Access")
							case message.EstablishmentCauseMCS_PriorityAccess:
								logger.IKELog.Debugln("AN-Parameter establishment cause: MCS Priority Access")
							default:
								logger.IKELog.Debugln("AN-Parameter establishment cause: Unknown. Treat as mo-Data")
								establishmentCause = message.EstablishmentCauseMO_Data
							}

							ngapEstablishmentCause := new(ngapType.RRCEstablishmentCause)
							ngapEstablishmentCause.Value = aper.Enumerated(establishmentCause)

							anParameters.EstablishmentCause = ngapEstablishmentCause
						} else {
							logger.IKELog.Warnln("AN-Parameter establishment cause field empty")
						}
					default:
						logger.IKELog.Warnln("unsupported AN-Parameter. Ignore")
					}

					// shift anParameterField
					anParameterField = anParameterField[2+parameterLength:]
				}
			}

			// shift codedData
			codedData = codedData[2+anParameterLength:]
		} else {
			logger.IKELog.Errorln("no AN-Parameter type or length specified")
			return 0, nil, nil, errors.New("error formatting")
		}

		if len(codedData) >= 2 {
			// Length of the NASPDU field
			nasPDULength := binary.BigEndian.Uint16(codedData[:2])

			if nasPDULength != 0 {
				nasPDUField := codedData[2:]

				// Bound checking
				if len(nasPDUField) < int(nasPDULength) {
					return 0, nil, nil, errors.New("error formatting")
				} else {
					nasPDUField = nasPDUField[:nasPDULength]
				}

				nasPDU = append(nasPDU, nasPDUField...)
			} else {
				logger.IKELog.Errorln("no NAS PDU included in EAP-5G packet")
				return 0, nil, nil, errors.New("no NAS PDU")
			}
		} else {
			logger.IKELog.Errorln("no NASPDU length specified")
			return 0, nil, nil, errors.New("error formatting")
		}

		return eap5GMessageID, anParameters, nasPDU, nil
	} else {
		return 0, nil, nil, errors.New("no data to decode")
	}
}
