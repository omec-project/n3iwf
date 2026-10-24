// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	n3iwfContext "github.com/omec-project/n3iwf/context"
	"github.com/omec-project/n3iwf/factory"
	ikeService "github.com/omec-project/n3iwf/ike/service"
	"github.com/omec-project/n3iwf/ike/xfrm"
	"github.com/omec-project/n3iwf/logger"
	ngapService "github.com/omec-project/n3iwf/ngap/service"
	nwucpService "github.com/omec-project/n3iwf/nwucp/service"
	nwuupService "github.com/omec-project/n3iwf/nwuup/service"
	"github.com/omec-project/n3iwf/util"
	ngapLogger "github.com/omec-project/ngap/v2/logger"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"github.com/vishvananda/netlink"
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
	utilLogger.ApplyLogSetting("N3IWF", cfgLogger.N3IWF, logger.InitLog, logger.SetLogLevel)
	utilLogger.ApplyLogSetting("NGAP", cfgLogger.NGAP, ngapLogger.NgapLog, ngapLogger.SetLogLevel)
	utilLogger.ApplyLogSetting("Util", cfgLogger.Util, utilLogger.UtilLog, utilLogger.SetLogLevel)
}

// Start launches all services and handles graceful shutdown. It returns an error if
// initialization or any service fails to start, after releasing what was already set up.
func (n3iwf *N3IWF) Start() error {
	logger.InitLog.Infoln("server started")
	var cancel context.CancelFunc
	n3iwfCtx := n3iwfContext.N3IWFSelf()
	n3iwfCtx.Ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	// Register before starting anything so a SIGTERM during startup is not lost
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChannel)

	// Initialization and the services start in a goroutine of their own so that a signal is
	// acted on from the moment it is registered, while a host name is still being resolved or
	// a service is still starting (NGAP waits for the AMF). The signal cancels n3iwfCtx.Ctx,
	// which every startup step observes, so startup returns promptly. It is always joined
	// before teardown begins: a step that outlived the shutdown could publish sockets after
	// Stop had run.
	startDone := make(chan error, 1)
	go func() { startDone <- n3iwf.startup(n3iwfCtx) }()

	var startErr error
	interrupted := false
	select {
	case startErr = <-startDone:
	case <-signalChannel:
		interrupted = true
		cancel()
		startErr = <-startDone
	}

	// The shutdown goroutine only starts once startup has returned: it stops the services, and
	// that must not race with a service that is still setting itself up.
	n3iwfCtx.Wg.Add(1)
	go n3iwf.ListenShutdownEvent(n3iwfCtx)

	if startErr != nil {
		// Let the shutdown goroutine stop what was started and remove the interfaces
		// before the process exits.
		cancel()
		waitWithTimeout(&n3iwfCtx.Wg, shutdownTimeout)
		if interrupted {
			logger.InitLog.Infoln("shutdown requested during startup")
			return nil
		}
		return startErr
	}
	logger.InitLog.Infoln("N3IWF running")

	if !interrupted {
		<-signalChannel
	}
	cancel()
	n3iwf.WaitRoutineStopped(n3iwfCtx)
	return nil
}

// startup initializes the context and the default XFRM interface, then starts the services
func (n3iwf *N3IWF) startup(n3iwfCtx *n3iwfContext.N3IWFContext) error {
	if !util.InitN3IWFContext(n3iwfCtx.Ctx) {
		if err := n3iwfCtx.Ctx.Err(); err != nil {
			return fmt.Errorf("initializing context cancelled: %w", err)
		}
		return errors.New("initializing context failed")
	}
	if err := n3iwfCtx.Ctx.Err(); err != nil {
		return fmt.Errorf("startup cancelled: %w", err)
	}
	if err := n3iwf.InitDefaultXfrmInterface(n3iwfCtx); err != nil {
		return fmt.Errorf("initiating XFRM interface for control plane failed: %w", err)
	}
	return n3iwf.startServices(n3iwfCtx)
}

// startServices starts the services in order. It stops at the first failure, or as soon as
// n3iwfCtx.Ctx is cancelled.
func (n3iwf *N3IWF) startServices(n3iwfCtx *n3iwfContext.N3IWFContext) error {
	services := []struct {
		name string
		run  func(*n3iwfContext.N3IWFContext, *sync.WaitGroup) error
	}{
		{"NGAP", ngapService.Run},
		{"NWu control plane", nwucpService.Run},
		{"NWu user plane", nwuupService.Run},
		{"IKE", ikeService.Run},
	}
	for _, svc := range services {
		if err := n3iwfCtx.Ctx.Err(); err != nil {
			return fmt.Errorf("start %s service cancelled: %w", svc.name, err)
		}
		if err := svc.run(n3iwfCtx, &n3iwfCtx.Wg); err != nil {
			return fmt.Errorf("start %s service failed: %w", svc.name, err)
		}
		logger.InitLog.Infof("%s service running", svc.name)
	}
	return nil
}

// shutdownTimeout bounds how long a failed startup waits for cleanup to finish
const shutdownTimeout = 10 * time.Second

// waitWithTimeout waits for wg, giving up after timeout
func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		logger.InitLog.Warnf("timed out after %s waiting for services to stop", timeout)
	}
}

// ListenShutdownEvent waits for shutdown and stops services
func (n3iwf *N3IWF) ListenShutdownEvent(n3iwfCtx *n3iwfContext.N3IWFContext) {
	defer n3iwfCtx.Wg.Done()
	<-n3iwfCtx.Ctx.Done()
	// Deferred calls run last-in first-out: a panic while stopping a service is recovered and
	// the interfaces are still removed.
	defer n3iwf.removeIPsecInterfaces(n3iwfCtx)
	defer util.RecoverWithLog(logger.InitLog)
	n3iwf.stopServiceConn(n3iwfCtx)
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

// stopServiceConn stops all running services. Each Stop is isolated because a service that
// failed to start, or never started, can panic when stopped, and that must not prevent the
// remaining services from being stopped.
func (n3iwf *N3IWF) stopServiceConn(n3iwfCtx *n3iwfContext.N3IWFContext) {
	logger.InitLog.Infoln("stopping service created by N3IWF")
	for _, stop := range []func(){
		func() { ngapService.Stop(n3iwfCtx) },
		func() { nwucpService.Stop(n3iwfCtx) },
		func() { nwuupService.Stop(n3iwfCtx) },
		func() { ikeService.Stop(n3iwfCtx) },
	} {
		func() {
			defer util.RecoverWithLog(logger.InitLog)
			stop()
		}()
	}
}
