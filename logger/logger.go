// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log         *zap.Logger
	AppLog      *zap.SugaredLogger
	InitLog     *zap.SugaredLogger
	CfgLog      *zap.SugaredLogger
	CtxLog      *zap.SugaredLogger
	NgapLog     *zap.SugaredLogger
	IKELog      *zap.SugaredLogger
	GTPLog      *zap.SugaredLogger
	NWuCPLog    *zap.SugaredLogger
	NWuUPLog    *zap.SugaredLogger
	RelayLog    *zap.SugaredLogger
	UtilLog     *zap.SugaredLogger
	atomicLevel zap.AtomicLevel
)

func init() {
	atomicLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	config := zap.Config{
		Level:            atomicLevel,
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	// Encoder configuration
	encCfg := &config.EncoderConfig
	encCfg.TimeKey = "timestamp"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.LevelKey = "level"
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	encCfg.CallerKey = "caller"
	encCfg.EncodeCaller = zapcore.ShortCallerEncoder
	encCfg.MessageKey = "message"
	encCfg.StacktraceKey = ""

	var err error
	log, err = config.Build()
	if err != nil {
		panic(err)
	}

	// Assign sugared loggers for each category
	AppLog = log.Sugar().With("component", "N3IWF", "category", "App")
	InitLog = log.Sugar().With("component", "N3IWF", "category", "Init")
	CfgLog = log.Sugar().With("component", "N3IWF", "category", "CFG")
	CtxLog = log.Sugar().With("component", "N3IWF", "category", "Context")
	NgapLog = log.Sugar().With("component", "N3IWF", "category", "NGAP")
	IKELog = log.Sugar().With("component", "N3IWF", "category", "IKE")
	GTPLog = log.Sugar().With("component", "N3IWF", "category", "GTP")
	NWuCPLog = log.Sugar().With("component", "N3IWF", "category", "NWuCP")
	NWuUPLog = log.Sugar().With("component", "N3IWF", "category", "NWuUP")
	RelayLog = log.Sugar().With("component", "N3IWF", "category", "Relay")
	UtilLog = log.Sugar().With("component", "N3IWF", "category", "Util")
}

// GetLogger returns the base zap.Logger
func GetLogger() *zap.Logger {
	return log
}

// SetLogLevel sets the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	atomicLevel.SetLevel(level)
}
