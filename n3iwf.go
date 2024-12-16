// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/service"
	"github.com/urfave/cli"
	"go.uber.org/zap"
)

var N3IWF = &service.N3IWF{}

var appLog *zap.SugaredLogger

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "n3iwf"
	appLog.Infoln(app.Name)
	app.Usage = "-free5gccfg common configuration file -n3iwfcfg n3iwf configuration file"
	app.Action = action
	app.Flags = N3IWF.GetCliCmd()
	if err := app.Run(os.Args); err != nil {
		appLog.Errorf("N3IWF run Error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := N3IWF.Initialize(c); err != nil {
		logger.CfgLog.Errorf("%+v", err)
		return fmt.Errorf("failed to initialize")
	}

	N3IWF.Start()

	return nil
}
