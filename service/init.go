// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"

	aperLogger "github.com/omec-project/aper/logger"
	"github.com/omec-project/n3iwf/factory"
	ike_service "github.com/omec-project/n3iwf/ike/service"
	"github.com/omec-project/n3iwf/logger"
	ngap_service "github.com/omec-project/n3iwf/ngap/service"
	nwucp_service "github.com/omec-project/n3iwf/nwucp/service"
	nwuup_service "github.com/omec-project/n3iwf/nwuup/service"
	"github.com/omec-project/n3iwf/util"
	ngapLogger "github.com/omec-project/ngap/logger"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type N3IWF struct{}

type (
	// Config information.
	Config struct {
		cfg string
	}
)

var config Config

var n3iwfCLi = []cli.Flag{
	&cli.StringFlag{
		Name:     "cfg",
		Usage:    "n3iwf config file",
		Required: true,
	},
}

func init() {
}

func (*N3IWF) GetCliCmd() (flags []cli.Flag) {
	return n3iwfCLi
}

func (n3iwf *N3IWF) Initialize(c *cli.Command) error {
	config = Config{
		cfg: c.String("cfg"),
	}

	absPath, err := filepath.Abs(config.cfg)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}

	if err := factory.InitConfigFactory(absPath); err != nil {
		return err
	}

	n3iwf.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	return nil
}

func (n3iwf *N3IWF) setLogLevel() {
	if factory.N3iwfConfig.Logger == nil {
		logger.InitLog.Warnln("N3IWF config without log level setting")
		return
	}

	if factory.N3iwfConfig.Logger.N3IWF != nil {
		if factory.N3iwfConfig.Logger.N3IWF.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.N3iwfConfig.Logger.N3IWF.DebugLevel); err != nil {
				logger.InitLog.Warnf("N3IWF Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.N3IWF.DebugLevel)
				logger.SetLogLevel(zap.InfoLevel)
			} else {
				logger.InitLog.Infof("N3IWF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("N3IWF Log level is default set to [info] level")
			logger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.N3iwfConfig.Logger.NGAP != nil {
		if factory.N3iwfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.N3iwfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(zap.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.N3iwfConfig.Logger.Aper != nil {
		if factory.N3iwfConfig.Logger.Aper.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.N3iwfConfig.Logger.Aper.DebugLevel); err != nil {
				aperLogger.AperLog.Warnf("Aper Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.Aper.DebugLevel)
				aperLogger.SetLogLevel(zap.InfoLevel)
			} else {
				aperLogger.SetLogLevel(level)
			}
		} else {
			aperLogger.AperLog.Warnln("Aper Log level not set. Default set to [info] level")
			aperLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.N3iwfConfig.Logger.Util != nil {
		if factory.N3iwfConfig.Logger.Util.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.N3iwfConfig.Logger.Util.DebugLevel); err != nil {
				utilLogger.UtilLog.Warnf("Util (drsm, fsm, etc.) Log level [%s] is invalid, set to [info] level",
					factory.N3iwfConfig.Logger.Util.DebugLevel)
				utilLogger.SetLogLevel(zap.InfoLevel)
			} else {
				utilLogger.SetLogLevel(level)
			}
		} else {
			utilLogger.UtilLog.Warnln("Util (drsm, fsm, etc.) Log level not set. Default set to [info] level")
			utilLogger.SetLogLevel(zap.InfoLevel)
		}
	}
}

func (n3iwf *N3IWF) FilterCli(c *cli.Command) (args []string) {
	for _, flag := range n3iwf.GetCliCmd() {
		name := flag.Names()[0]
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (n3iwf *N3IWF) Start() {
	logger.InitLog.Infoln("server started")

	if !util.InitN3IWFContext() {
		logger.InitLog.Errorln("initializing context failed")
		return
	}

	wg := sync.WaitGroup{}

	// NGAP
	if err := ngap_service.Run(); err != nil {
		logger.InitLog.Errorf("start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NGAP service running")
	wg.Add(1)

	// Relay listeners
	// Control plane
	if err := nwucp_service.Run(); err != nil {
		logger.InitLog.Errorf("listen NWu control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NAS TCP server successfully started")
	wg.Add(1)

	// User plane
	if err := nwuup_service.Run(); err != nil {
		logger.InitLog.Errorf("listen NWu user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("listening NWu user plane traffic")
	wg.Add(1)

	// IKE
	if err := ike_service.Run(); err != nil {
		logger.InitLog.Errorf("start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("IKE service running")
	wg.Add(1)

	logger.InitLog.Infoln("N3IWF running")

	wg.Wait()
}

func (n3iwf *N3IWF) Exec(c *cli.Command) error {
	// N3IWF.Initialize(cfgPath, c)

	logger.InitLog.Debugln("args:", c.String("cfg"))
	args := n3iwf.FilterCli(c)
	logger.InitLog.Debugln("filter:", args)
	command := exec.Command("n3iwf", args...)

	wg := sync.WaitGroup{}
	wg.Add(3)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			logger.InitLog.Debugln(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			logger.InitLog.Debugln(in.Text())
		}
		wg.Done()
	}()

	go func() {
		if errCom := command.Start(); errCom != nil {
			logger.InitLog.Errorf("N3IWF start error: %v", errCom)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
