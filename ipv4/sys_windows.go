// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"

	"golang.org/x/sys/windows"
)

const (
	sizeofIPMreq       = 0x8
	sizeofIPMreqSource = 0xc
	sizeofInetPktinfo  = 0x8

	// See https://learn.microsoft.com/zh-cn/windows/win32/winsock/ipproto-ip-socket-options
	// https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/ws2ipdef.h#L149
	sysIP_RECVTTL = 0x15
)

type inetPktinfo struct {
	Addr    [4]byte
	Ifindex int32
}

type ipMreq struct {
	Multiaddr [4]byte
	Interface [4]byte
}

type ipMreqSource struct {
	Multiaddr  [4]byte
	Sourceaddr [4]byte
	Interface  [4]byte
}

// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms738586(v=vs.85).aspx
var (
	ctlOpts = [ctlMax]ctlOpt{
		ctlTTL:        {windows.IP_TTL, 1, marshalTTL, parseTTL},
		ctlPacketInfo: {windows.IP_PKTINFO, sizeofInetPktinfo, marshalPacketInfo, parsePacketInfo},
	}

	sockOpts = map[int]*sockOpt{
		ssoTOS:                {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_TOS, Len: 4}},
		ssoTTL:                {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_TTL, Len: 4}},
		ssoMulticastTTL:       {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_MULTICAST_TTL, Len: 4}},
		ssoMulticastInterface: {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_MULTICAST_IF, Len: 4}},
		ssoMulticastLoopback:  {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_MULTICAST_LOOP, Len: 4}},
		ssoHeaderPrepend:      {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_HDRINCL, Len: 4}},
		ssoJoinGroup:          {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_ADD_MEMBERSHIP, Len: sizeofIPMreq}, typ: ssoTypeIPMreq},
		ssoLeaveGroup:         {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_DROP_MEMBERSHIP, Len: sizeofIPMreq}, typ: ssoTypeIPMreq},
		ssoPacketInfo:         {Option: socket.Option{Level: iana.ProtocolIP, Name: windows.IP_PKTINFO, Len: 4}},
		ssoReceiveTTL:         {Option: socket.Option{Level: iana.ProtocolIP, Name: sysIP_RECVTTL, Len: 4}},
	}
)

func (pi *inetPktinfo) setIfindex(i int) {
	pi.Ifindex = int32(i)
}
