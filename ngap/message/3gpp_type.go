// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

// AN-Parameter Types
const (
	ANParametersTypeGUAMI              = iota + 1 // 1
	ANParametersTypeSelectedPLMNID                // 2
	ANParametersTypeRequestedNSSAI                // 3
	ANParametersTypeEstablishmentCause            // 4
)

// AN-Parameter Lengths
const (
	ANParametersLenGUAMI    = 6
	ANParametersLenPLMNID   = 3
	ANParametersLenEstCause = 1
)

// Establishment Cause Types
const (
	EstablishmentCauseEmergency = iota
	EstablishmentCauseHighPriorityAccess
	_                                    // 2 unused
	EstablishmentCauseMO_Signalling      // 3
	EstablishmentCauseMO_Data            // 4
	_                                    // 5 unused
	_                                    // 6 unused
	_                                    // 7 unused
	EstablishmentCauseMPS_PriorityAccess // 8
	EstablishmentCauseMCS_PriorityAccess // 9
)

// Maximum number of PDU Sessions
const MaxNumOfPDUSessions = 256
