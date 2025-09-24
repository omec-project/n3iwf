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
	N3iwfInfo            context.N3iwfNfInfo        `yaml:"n3iwfInformation"`           // N3IWF network function info
	AmfSctpAddresses     []context.AmfSctpAddresses `yaml:"amfSctpAddresses"`           // AMF SCTP addresses
	LocalSctpAddress     string                     `yaml:"localSctpAddress,omitempty"` // Local SCTP address (optional)
	IkeBindAddress       string                     `yaml:"ikeBindAddress"`             // IKE bind address
	IpSecAddress         string                     `yaml:"ipSecAddress"`               // IPsec address range (e.g. 10.0.1.0/24)
	GtpBindAddress       string                     `yaml:"gtpBindAddress"`             // GTP bind address
	TcpPort              uint16                     `yaml:"nasTcpPort"`                 // NAS TCP port
	Fqdn                 string                     `yaml:"fqdn"`                       // FQDN (e.g. n3iwf.aether.org)
	PrivateKey           string                     `yaml:"privateKey"`                 // Private key path
	CertificateAuthority string                     `yaml:"certificateAuthority"`       // CA certificate path
	Certificate          string                     `yaml:"certificate"`                // Certificate path
	XfrmInterfaceName    string                     `yaml:"xfrmInterfaceName"`          // XFRM interface name
	XfrmInterfaceId      uint32                     `yaml:"xfrmInterfaceId"`            // XFRM interface ID (must be != 0)
	LivenessCheck        TimerValue                 `yaml:"livenessCheck"`              // Liveness check settings
}

// TimerValue configures liveness check timers
type TimerValue struct {
	Enable        bool          `yaml:"enable"`                  // Enable liveness check
	TransFreq     time.Duration `yaml:"transFreq"`               // Transmission frequency
	MaxRetryTimes int32         `yaml:"maxRetryTimes,omitempty"` // Maximum retry times (optional)
}

// getVersion returns the configuration version if set, otherwise returns empty string
func (c Config) getVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
