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
	n3iwfContext "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	ikeService "github.com/omec-project/n3iwf/ike/service"
	"github.com/omec-project/n3iwf/ike/xfrm"
	"github.com/omec-project/n3iwf/logger"
	ngapService "github.com/omec-project/n3iwf/ngap/service"
	nwucpService "github.com/omec-project/n3iwf/nwucp/service"
	nwuupService "github.com/omec-project/n3iwf/nwuup/service"
	"github.com/omec-project/n3iwf/util"
	ngapLogger "github.com/omec-project/ngap/logger"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// N3IWF main struct
type N3IWF struct{}

// Config holds configuration file path
type Config struct {
	cfg string
}

var config Config

var n3iwfCLi = []cli.Flag{
	&cli.StringFlag{
		Name:     "cfg",
		Usage:    "n3iwf config file",
		Required: true,
	},
}

func (*N3IWF) GetCliCmd() (flags []cli.Flag) {
	return n3iwfCLi
}

// Initialize loads config and sets log levels
func (n3iwf *N3IWF) Initialize(c *cli.Command) error {
	config = Config{cfg: c.String("cfg")}
	absPath, err := filepath.Abs(config.cfg)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}
	if err := factory.InitConfigFactory(absPath); err != nil {
		return err
	}
	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}
	n3iwf.setLogLevel()
	return nil
}

// setLogLevel configures log levels for all modules
func (n3iwf *N3IWF) setLogLevel() {
	cfgLogger := factory.N3iwfConfig.Logger
	if cfgLogger == nil {
		logger.InitLog.Warnln("N3IWF config without log level setting")
		return
	}
	setModuleLogLevel(cfgLogger.N3IWF, logger.InitLog, logger.SetLogLevel, "N3IWF")
	setModuleLogLevel(cfgLogger.NGAP, ngapLogger.NgapLog, ngapLogger.SetLogLevel, "NGAP")
	setModuleLogLevel(cfgLogger.Aper, aperLogger.AperLog, aperLogger.SetLogLevel, "Aper")
	setModuleLogLevel(cfgLogger.Util, utilLogger.UtilLog, utilLogger.SetLogLevel, "Util (drsm, fsm, etc.)")
}

// setModuleLogLevel is a helper to reduce repetition in log level setup
func setModuleLogLevel(moduleCfg *utilLogger.LogSetting, logObj *zap.SugaredLogger, setLevel func(zapcore.Level), moduleName string) {
	if moduleCfg == nil {
		logObj.Warnf("%s Log level not set. Default set to [info] level", moduleName)
		setLevel(zap.InfoLevel)
		return
	}
	if moduleCfg.DebugLevel != "" {
		level, err := zapcore.ParseLevel(moduleCfg.DebugLevel)
		if err != nil {
			logObj.Warnf("%s Log level [%s] is invalid, set to [info] level", moduleName, moduleCfg.DebugLevel)
			setLevel(zap.InfoLevel)
		} else {
			logObj.Infof("%s Log level is set to [%s] level", moduleName, level)
			setLevel(level)
		}
	} else {
		logObj.Warnf("%s Log level not set. Default set to [info] level", moduleName)
		setLevel(zap.InfoLevel)
	}
}

// FilterCli returns CLI args for flags
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

// Start launches all services and handles graceful shutdown
func (n3iwf *N3IWF) Start() {
	logger.InitLog.Infoln("server started")
	var cancel context.CancelFunc
	n3iwfCtx := n3iwfContext.N3IWFSelf()
	n3iwfCtx.Ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if !util.InitN3IWFContext() {
		logger.InitLog.Errorln("initializing context failed")
		return
	}
	if err := n3iwf.InitDefaultXfrmInterface(n3iwfCtx); err != nil {
		logger.InitLog.Errorf("initiating XFRM interface for control plane failed: %+v", err)
		return
	}
	n3iwfCtx.Wg.Add(1)
	go n3iwf.ListenShutdownEvent(n3iwfCtx)
	if err := ngapService.Run(n3iwfCtx, &n3iwfCtx.Wg); err != nil {
		logger.InitLog.Errorf("start NGAP service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NGAP service running")
	if err := nwucpService.Run(n3iwfCtx, &n3iwfCtx.Wg); err != nil {
		logger.InitLog.Errorf("listen NWu control plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("NAS TCP server successfully started")
	if err := nwuupService.Run(n3iwfCtx, &n3iwfCtx.Wg); err != nil {
		logger.InitLog.Errorf("listen NWu user plane traffic failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("GTP service running")
	if err := ikeService.Run(n3iwfCtx, &n3iwfCtx.Wg); err != nil {
		logger.InitLog.Errorf("start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Infoln("IKE service running")
	logger.InitLog.Infoln("N3IWF running")

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	<-signalChannel
	cancel()
	n3iwf.WaitRoutineStopped(n3iwfCtx)
}

// ListenShutdownEvent waits for shutdown and stops services
func (n3iwf *N3IWF) ListenShutdownEvent(n3iwfCtx *n3iwfContext.N3IWFContext) {
	defer util.RecoverWithLog(logger.InitLog)
	<-n3iwfCtx.Ctx.Done()
	n3iwf.stopServiceConn(n3iwfCtx)
	n3iwf.removeIPsecInterfaces(n3iwfCtx)
}

// WaitRoutineStopped waits for all goroutines and terminates
func (n3iwf *N3IWF) WaitRoutineStopped(n3iwfCtx *n3iwfContext.N3IWFContext) {
	n3iwfCtx.Wg.Wait()
	time.Sleep(2 * time.Second)
	os.Exit(0)
}

// InitDefaultXfrmInterface sets up default IPsec interface for Control Plane
func (n3iwf *N3IWF) InitDefaultXfrmInterface(n3iwfCtx *n3iwfContext.N3IWFContext) error {
	ipAddr := net.ParseIP(n3iwfCtx.IpSecGatewayAddress).To4()
	ipNet := net.IPNet{IP: ipAddr, Mask: n3iwfCtx.Subnet.Mask}
	ifaceName := fmt.Sprintf("%s-default", n3iwfCtx.XfrmInterfaceName)
	link, err := xfrm.SetupIPsecXfrmi(ifaceName, n3iwfCtx.XfrmParentIfaceName, n3iwfCtx.XfrmInterfaceId, ipNet)
	if err != nil {
		logger.InitLog.Errorf("setup XFRM interface %s fail: %+v", ifaceName, err)
		return err
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: n3iwfCtx.Subnet}
	if err := netlink.RouteAdd(route); err != nil {
		logger.InitLog.Warnf("netlink.RouteAdd: %+v", err)
	}
	logger.InitLog.Infof("setup XFRM interface %s", ifaceName)
	n3iwfCtx.XfrmIfaces.LoadOrStore(n3iwfCtx.XfrmInterfaceId, link)
	n3iwfCtx.XfrmIfaceIdOffsetForUP = 1
	return nil
}

// removeIPsecInterfaces deletes all IPsec interfaces
func (n3iwf *N3IWF) removeIPsecInterfaces(n3iwfCtx *n3iwfContext.N3IWFContext) {
	logger.InitLog.Infoln("deleting interfaces created by N3IWF")
	n3iwfCtx.XfrmIfaces.Range(func(key, value any) bool {
		iface := value.(netlink.Link)
		if err := netlink.LinkDel(iface); err != nil {
			logger.InitLog.Errorf("delete interface %s failed: %+v", iface.Attrs().Name, err)
		} else {
			logger.InitLog.Infof("delete interface: %s", iface.Attrs().Name)
		}
		return true
	})
}

// stopServiceConn stops all running services
func (n3iwf *N3IWF) stopServiceConn(n3iwfCtx *n3iwfContext.N3IWFContext) {
	logger.InitLog.Infoln("stopping service created by N3IWF")
	ngapService.Stop(n3iwfCtx)
	nwucpService.Stop(n3iwfCtx)
	nwuupService.Stop(n3iwfCtx)
	ikeService.Stop(n3iwfCtx)
}
