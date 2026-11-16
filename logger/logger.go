// Copyright (C) 2024-Present Intel Corporation
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	utilLogger "github.com/omec-project/util/logger"
	"go.uber.org/zap/zapcore"
)

var component = utilLogger.NewComponent("N3IWF")

var (
	AppLog   = component.Category("App")
	InitLog  = component.Category("Init")
	CfgLog   = component.Category("CFG")
	CtxLog   = component.Category("Context")
	NgapLog  = component.Category("NGAP")
	IKELog   = component.Category("IKE")
	GTPLog   = component.Category("GTP")
	NWuCPLog = component.Category("NWuCP")
	NWuUPLog = component.Category("NWuUP")
	RelayLog = component.Category("Relay")
	UtilLog  = component.Category("Util")
)

// SetLogLevel sets the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	component.SetLevel(level)
}
