// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"time"

	"github.com/omec-project/n3iwf/context"
	"github.com/omec-project/util/logger"
)

const N3IWF_EXPECTED_CONFIG_VERSION = "1.0.0"

// Config holds the main configuration structure for N3IWF
// Includes general info, configuration parameters, and logger settings
// Info and Configuration are required, Logger is optional
type Config struct {
	Info          *Info          `yaml:"info"`          // General information
	Configuration *Configuration `yaml:"configuration"` // Main configuration
	Logger        *logger.Logger `yaml:"logger"`        // Logger settings
}

// Info provides metadata about the configuration
// Version and Description are optional
type Info struct {
	Version     string `yaml:"version,omitempty"`     // Config version
	Description string `yaml:"description,omitempty"` // Description
}

// Configuration contains all N3IWF-specific settings
type Configuration struct {
	CertificateAuthority string                     `yaml:"certificateAuthority"`
	Certificate          string                     `yaml:"certificate"`
	LocalSctpAddress     string                     `yaml:"localSctpAddress,omitempty"`
	IkeBindAddress       string                     `yaml:"ikeBindAddress"`
	IpSecAddress         string                     `yaml:"ipSecAddress"`
	GtpBindAddress       string                     `yaml:"gtpBindAddress"`
	PrivateKey           string                     `yaml:"privateKey"`
	Fqdn                 string                     `yaml:"fqdn"`
	XfrmInterfaceName    string                     `yaml:"xfrmInterfaceName"`
	N3iwfInfo            context.N3iwfNfInfo        `yaml:"n3iwfInformation"`
	AmfSctpAddresses     []context.AmfSctpAddresses `yaml:"amfSctpAddresses"`
	LivenessCheck        TimerValue                 `yaml:"livenessCheck"`
	XfrmInterfaceId      uint32                     `yaml:"xfrmInterfaceId"`
	TcpPort              uint16                     `yaml:"nasTcpPort"`
}

// TimerValue configures liveness check timers
type TimerValue struct {
	TransFreq     time.Duration `yaml:"transFreq"`
	MaxRetryTimes int32         `yaml:"maxRetryTimes,omitempty"`
	Enable        bool          `yaml:"enable"`
}

// getVersion returns the configuration version if set, otherwise returns empty string
func (c Config) getVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
