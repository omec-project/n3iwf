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

// N3iwfConfig holds the loaded configuration
var N3iwfConfig Config

// InitConfigFactory loads and parses the configuration file into N3iwfConfig
func InitConfigFactory(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	N3iwfConfig = cfg
	return nil
}

// CheckConfigVersion validates the loaded config version
func CheckConfigVersion() error {
	currentVersion := N3iwfConfig.getVersion()
	if currentVersion != N3IWF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]", currentVersion, N3IWF_EXPECTED_CONFIG_VERSION)
	}
	logger.CfgLog.Infof("config version [%s]", currentVersion)
	return nil
}
