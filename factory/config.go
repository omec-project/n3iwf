// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
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
	IpSecAddress         string                     `yaml:"ipSecAddress"`	        // e.g. 10.0.1.0/24
	GtpBindAddress       string                     `yaml:"gtpBindAddress"`
	TcpPort              uint16                     `yaml:"nasTcpPort"`
	Fqdn                 string                     `yaml:"fqdn"`                 // e.g. n3iwf.aether.org
	PrivateKey           string                     `yaml:"privateKey"`           // file path
	CertificateAuthority string                     `yaml:"certificateAuthority"` // file path
	Certificate          string                     `yaml:"certificate"`          // file path
	InterfaceMark        uint32                     `yaml:"ipSecInterfaceMark"`   // must be != 0, if not specified, set to `7`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
