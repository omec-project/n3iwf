// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	aperLogger "github.com/omec-project/aper/logger"
	n3iwf_context "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	ike_service "github.com/omec-project/n3iwf/ike/service"
	"github.com/omec-project/n3iwf/ike/xfrm"
	"github.com/omec-project/n3iwf/logger"
	ngap_service "github.com/omec-project/n3iwf/ngap/service"
	nwucp_service "github.com/omec-project/n3iwf/nwucp/service"
	nwuup_service "github.com/omec-project/n3iwf/nwuup/service"
	"github.com/omec-project/n3iwf/util"
	ngapLogger "github.com/omec-project/ngap/logger"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"github.com/vishvananda/netlink"
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

	var cancel context.CancelFunc
	n3iwfContext := n3iwf_context.N3IWFSelf()
	n3iwfContext.Ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	if !util.InitN3IWFContext() {
		logger.InitLog.Errorln("initializing context failed")
		return
	}

	if err := n3iwf.InitDefaultXfrmInterface(n3iwfContext); err != nil {
		logger.InitLog.Errorf("initiating XFRM interface for control plane failed: %+v", err)
		return
	}

	n3iwfContext.Wg.Add(1)
	// Graceful Shutdown
	go n3iwf.ListenShutdownEvent(n3iwfContext)

	// NGAP
	if err := ngap_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NGAP service running")

	// Relay listeners
	// Control plane
	if err := nwucp_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("listen NWu control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NAS TCP server successfully started")

	// User plane
	if err := nwuup_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("listen NWu user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("GTP service running")

	// IKE
	if err := ike_service.Run(&n3iwfContext.Wg); err != nil {
		logger.InitLog.Errorf("start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("IKE service running")
	logger.InitLog.Infoln("N3IWF running")

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel

	cancel()
	n3iwf.WaitRoutineStopped(n3iwfContext)
}

func (n3iwf *N3IWF) ListenShutdownEvent(n3iwfContext *n3iwf_context.N3IWFContext) {
	defer util.RecoverWithLog(logger.InitLog)

	<-n3iwfContext.Ctx.Done()
	StopServiceConn(n3iwfContext)
}

func (n3iwf *N3IWF) WaitRoutineStopped(n3iwfContext *n3iwf_context.N3IWFContext) {
	n3iwfContext.Wg.Wait()
	// Waiting for negotiatioon with netlink for deleting interfaces
	n3iwf.Terminate(n3iwfContext)
	time.Sleep(2 * time.Second)
	os.Exit(0)
}

func (n3iwf *N3IWF) InitDefaultXfrmInterface(n3iwfContext *n3iwf_context.N3IWFContext) error {
	// Setup default IPsec interface for Control Plane
	var linkIPSec netlink.Link
	var err error
	n3iwfIPAddr := net.ParseIP(n3iwfContext.IpSecGatewayAddress).To4()
	n3iwfIPAddrAndSubnet := net.IPNet{IP: n3iwfIPAddr, Mask: n3iwfContext.Subnet.Mask}
	newXfrmiName := fmt.Sprintf("%s-default", n3iwfContext.XfrmInterfaceName)

	if linkIPSec, err = xfrm.SetupIPsecXfrmi(newXfrmiName, n3iwfContext.XfrmParentIfaceName,
		n3iwfContext.XfrmInterfaceId, n3iwfIPAddrAndSubnet); err != nil {
		logger.InitLog.Errorf("setup XFRM interface %s fail: %+v", newXfrmiName, err)
		return err
	}

	route := &netlink.Route{
		LinkIndex: linkIPSec.Attrs().Index,
		Dst:       n3iwfContext.Subnet,
	}

	if err := netlink.RouteAdd(route); err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", err)
	}

	logger.InitLog.Infof("setup XFRM interface %s", newXfrmiName)

	n3iwfContext.XfrmIfaces.LoadOrStore(n3iwfContext.XfrmInterfaceId, linkIPSec)
	n3iwfContext.XfrmIfaceIdOffsetForUP = 1

	return nil
}

func (n3iwf *N3IWF) removeIPsecInterfaces(n3iwfContext *n3iwf_context.N3IWFContext) {
	n3iwfContext.XfrmIfaces.Range(
		func(key, value any) bool {
			iface := value.(netlink.Link)
			if err := netlink.LinkDel(iface); err != nil {
				logger.InitLog.Errorf("delete interface %s fail: %+v", iface.Attrs().Name, err)
			} else {
				logger.InitLog.Infof("delete interface: %s", iface.Attrs().Name)
			}
			return true
		})
}

func (n3iwf *N3IWF) Terminate(n3iwfContext *n3iwf_context.N3IWFContext) {
	logger.InitLog.Infoln("terminating N3IWF")
	logger.InitLog.Infoln("deleting interfaces created by N3IWF")
	n3iwf.removeIPsecInterfaces(n3iwfContext)
	logger.InitLog.Info("N3IWF terminated")
}

func StopServiceConn(n3iwfContext *n3iwf_context.N3IWFContext) {
	logger.InitLog.Infoln("stopping service created by N3IWF")
	ngap_service.Stop(n3iwfContext)
	nwucp_service.Stop(n3iwfContext)
	nwuup_service.Stop(n3iwfContext)
	ike_service.Stop(n3iwfContext)
}
