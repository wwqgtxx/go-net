// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6

import (
	"net"
	"syscall"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"

	"golang.org/x/sys/windows"
)

const (
	sizeofSockaddrInet6 = 0x1c
	sizeofInet6Pktinfo  = 0x14

	sizeofIPv6Mreq     = 0x14
	sizeofIPv6Mtuinfo  = 0x20
	sizeofICMPv6Filter = 0
)

type sockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

type inet6Pktinfo struct {
	Addr    [16]byte /* in6_addr */
	Ifindex int32
}

type ipv6Mreq struct {
	Multiaddr [16]byte /* in6_addr */
	Interface uint32
}

type ipv6Mtuinfo struct {
	Addr sockaddrInet6
	Mtu  uint32
}

type icmpv6Filter struct {
	// TODO(mikio): implement this
}

var (
	ctlOpts = [ctlMax]ctlOpt{
		ctlPacketInfo: {windows.IPV6_PKTINFO, sizeofInet6Pktinfo, marshalPacketInfo, parsePacketInfo},
	}

	sockOpts = map[int]*sockOpt{
		ssoHopLimit:           {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_UNICAST_HOPS, Len: 4}},
		ssoMulticastInterface: {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_MULTICAST_IF, Len: 4}},
		ssoMulticastHopLimit:  {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_MULTICAST_HOPS, Len: 4}},
		ssoMulticastLoopback:  {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_MULTICAST_LOOP, Len: 4}},
		ssoJoinGroup:          {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_JOIN_GROUP, Len: sizeofIPv6Mreq}, typ: ssoTypeIPMreq},
		ssoLeaveGroup:         {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_LEAVE_GROUP, Len: sizeofIPv6Mreq}, typ: ssoTypeIPMreq},
		ssoReceivePacketInfo:  {Option: socket.Option{Level: iana.ProtocolIPv6, Name: windows.IPV6_PKTINFO, Len: 4}},
	}
)

func (pi *inet6Pktinfo) setIfindex(i int) {
	pi.Ifindex = int32(i)
}

func (sa *sockaddrInet6) setSockaddr(ip net.IP, i int) {
	sa.Family = syscall.AF_INET6
	copy(sa.Addr[:], ip)
	sa.Scope_id = uint32(i)
}

func (mreq *ipv6Mreq) setIfindex(i int) {
	mreq.Interface = uint32(i)
}
