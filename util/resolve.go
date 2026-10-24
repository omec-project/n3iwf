// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// ResolveUDPAddrContext is net.ResolveUDPAddr that gives up when ctx is cancelled. Resolving
// a host name can block for as long as the resolver takes, and startup must stay abortable
// by a shutdown request. Like net.ResolveUDPAddr it prefers an IPv4 address.
func ResolveUDPAddrContext(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}
	addr, err := lookupAddr(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: addr.AsSlice(), Port: port, Zone: addr.Zone()}, nil
}

// ResolveIPAddrContext is net.ResolveIPAddr that gives up when ctx is cancelled. network is
// "ip", "ip4" or "ip6". Like net.ResolveIPAddr it prefers an IPv4 address.
func ResolveIPAddrContext(ctx context.Context, network, host string) (*net.IPAddr, error) {
	addr, err := lookupAddr(ctx, network, host)
	if err != nil {
		return nil, err
	}
	return &net.IPAddr{IP: addr.AsSlice(), Zone: addr.Zone()}, nil
}

// lookupAddr parses host as an IP literal, or else looks it up honouring ctx
func lookupAddr(ctx context.Context, network, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if (network == "ip4" && !addr.Is4()) || (network == "ip6" && !addr.Is6()) {
			return netip.Addr{}, fmt.Errorf("address %q does not match network %q", host, network)
		}
		return addr, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no address found for %q", host)
	}
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	return addrs[0], nil
}
