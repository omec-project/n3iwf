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

const (
	N3IWF_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
	Logger        *logger.Logger `yaml:"logger"`
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

type Configuration struct {
	N3iwfInfo            context.N3iwfNfInfo        `yaml:"n3iwfInformation"`
	AmfSctpAddresses     []context.AmfSctpAddresses `yaml:"amfSctpAddresses"`
	LocalSctpAddress     string                     `yaml:"localSctpAddress"`
	IkeBindAddress       string                     `yaml:"ikeBindAddress"`
	IpSecAddress         string                     `yaml:"ipSecAddress"` // e.g. 10.0.1.0/24
	GtpBindAddress       string                     `yaml:"gtpBindAddress"`
	TcpPort              uint16                     `yaml:"nasTcpPort"`
	Fqdn                 string                     `yaml:"fqdn"` // e.g. n3iwf.aether.org
	PrivateKey           string                     `yaml:"privateKey"`
	CertificateAuthority string                     `yaml:"certificateAuthority"`
	Certificate          string                     `yaml:"certificate"`
	XfrmInterfaceName    string                     `yaml:"xfrmInterfaceName"`
	XfrmInterfaceId      uint32                     `yaml:"xfrmInterfaceId"` // must be != 0
	LivenessCheck        TimerValue                 `yaml:"livenessCheck"`
}

type TimerValue struct {
	Enable        bool          `yaml:"enable"`
	TransFreq     time.Duration `yaml:"transFreq"`
	MaxRetryTimes int32         `yaml:"maxRetryTimes,omitempty"`
}

func (c *Config) getVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
