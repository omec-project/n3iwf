// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"
	"os"

	"github.com/omec-project/n3iwf/logger"
	"go.yaml.in/yaml/v4"
)

var N3iwfConfig Config

func InitConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	N3iwfConfig = Config{}
	if err = yaml.Unmarshal(content, &N3iwfConfig); err != nil {
		return err
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := N3iwfConfig.getVersion()

	if currentVersion != N3IWF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]",
			currentVersion, N3IWF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
