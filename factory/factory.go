// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"
	"os"

	"github.com/omec-project/n3iwf/logger"
	"gopkg.in/yaml.v2"
)

var N3iwfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := os.ReadFile(f); err != nil {
		return err
	} else {
		N3iwfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &N3iwfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := N3iwfConfig.GetVersion()

	if currentVersion != N3IWF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]",
			currentVersion, N3IWF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
