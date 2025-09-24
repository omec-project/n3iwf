// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"github.com/omec-project/ngap/aper"
	"github.com/omec-project/ngap/ngapType"
)

// Helper function to append items to lists
func appendPDUSessionResourceItem(list any, pduSessionID int64, transfer []byte) {
	switch l := list.(type) {
	case *ngapType.PDUSessionResourceSetupListCxtRes:
		item := ngapType.PDUSessionResourceSetupItemCxtRes{
			PDUSessionID:                            ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupResponseTransfer: transfer,
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceFailedToSetupListCxtRes:
		item := ngapType.PDUSessionResourceFailedToSetupItemCxtRes{
			PDUSessionID: ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupUnsuccessfulTransfer: transfer,
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceFailedToSetupListCxtFail:
		item := ngapType.PDUSessionResourceFailedToSetupItemCxtFail{
			PDUSessionID: ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupUnsuccessfulTransfer: transfer,
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceSetupListSURes:
		item := ngapType.PDUSessionResourceSetupItemSURes{
			PDUSessionID:                            ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupResponseTransfer: transfer,
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceFailedToSetupListSURes:
		item := ngapType.PDUSessionResourceFailedToSetupItemSURes{
			PDUSessionID: ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupUnsuccessfulTransfer: transfer,
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceModifyListModRes:
		item := ngapType.PDUSessionResourceModifyItemModRes{
			PDUSessionID:                             ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceModifyResponseTransfer: aper.OctetString(transfer),
		}
		l.List = append(l.List, item)
	case *ngapType.PDUSessionResourceFailedToModifyListModRes:
		item := ngapType.PDUSessionResourceFailedToModifyItemModRes{
			PDUSessionID: ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceModifyUnsuccessfulTransfer: transfer,
		}
		l.List = append(l.List, item)
	}
}

func AppendPDUSessionResourceSetupListCxtRes(list *ngapType.PDUSessionResourceSetupListCxtRes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceFailedToSetupListCxtRes(list *ngapType.PDUSessionResourceFailedToSetupListCxtRes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceFailedToSetupListCxtfail(list *ngapType.PDUSessionResourceFailedToSetupListCxtFail, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceSetupListSURes(list *ngapType.PDUSessionResourceSetupListSURes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceFailedToSetupListSURes(list *ngapType.PDUSessionResourceFailedToSetupListSURes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceModifyListModRes(list *ngapType.PDUSessionResourceModifyListModRes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}

func AppendPDUSessionResourceFailedToModifyListModRes(list *ngapType.PDUSessionResourceFailedToModifyListModRes, pduSessionID int64, transfer []byte) {
	appendPDUSessionResourceItem(list, pduSessionID, transfer)
}
