// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/omec-project/n3iwf/logger"
	"github.com/omec-project/n3iwf/service"
	"github.com/urfave/cli/v3"
)

// N3IWF is the main service instance
var N3IWF = &service.N3IWF{}

func main() {
	// Set up CLI application
	app := &cli.Command{}
	app.Name = "n3iwf"
	logger.AppLog.Infof("starting Non-3GPP Interworking Function: %s", app.Name)
	app.Usage = "Non-3GPP Interworking Function"
	app.UsageText = "n3iwf -cfg <n3iwf_config_file.conf>"
	app.Action = action
	app.Flags = N3IWF.GetCliCmd()

	if err := app.Run(context.Background(), os.Args); err != nil {
		logger.AppLog.Fatalf("N3IWF run error: %v", err)
	}
}

// action initializes and starts the N3IWF service
func action(ctx context.Context, c *cli.Command) error {
	if err := N3IWF.Initialize(c); err != nil {
		logger.CfgLog.Errorf("initialization error: %+v", err)
		return fmt.Errorf("failed to initialize N3IWF: %w", err)
	}

	N3IWF.Start()
	return nil
}
