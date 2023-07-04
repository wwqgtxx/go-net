// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6

import (
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"
	"golang.org/x/sys/windows"
	"net"
	"unsafe"
)

func setControlMessage(c *socket.Conn, opt *rawOpt, cf ControlFlags, on bool) error {
	opt.Lock()
	defer opt.Unlock()
	if so, ok := sockOpts[ssoReceiveTrafficClass]; ok && cf&FlagTrafficClass != 0 {
		if err := so.SetInt(c, boolint(on)); err != nil {
			return err
		}
		if on {
			opt.set(FlagTrafficClass)
		} else {
			opt.clear(FlagTrafficClass)
		}
	}
	if so, ok := sockOpts[ssoReceiveHopLimit]; ok && cf&FlagHopLimit != 0 {
		if err := so.SetInt(c, boolint(on)); err != nil {
			return err
		}
		if on {
			opt.set(FlagHopLimit)
		} else {
			opt.clear(FlagHopLimit)
		}
	}
	if so, ok := sockOpts[ssoReceivePacketInfo]; ok && cf&flagPacketInfo != 0 {
		if err := so.SetInt(c, boolint(on)); err != nil {
			return err
		}
		if on {
			opt.set(cf & flagPacketInfo)
		} else {
			opt.clear(cf & flagPacketInfo)
		}
	}
	if so, ok := sockOpts[ssoReceivePathMTU]; ok && cf&FlagPathMTU != 0 {
		if err := so.SetInt(c, boolint(on)); err != nil {
			return err
		}
		if on {
			opt.set(FlagPathMTU)
		} else {
			opt.clear(FlagPathMTU)
		}
	}
	return nil
}

func marshalPacketInfo(b []byte, cm *ControlMessage) []byte {
	m := socket.ControlMessage(b)
	m.MarshalHeader(iana.ProtocolIPv6, windows.IPV6_PKTINFO, sizeofInet6Pktinfo)
	if cm != nil {
		pi := (*inet6Pktinfo)(unsafe.Pointer(&m.Data(sizeofInet6Pktinfo)[0]))
		if ip := cm.Src.To16(); ip != nil && ip.To4() == nil {
			if cm.IfIndex > 0 {
				intf, _ := net.InterfaceByIndex(cm.IfIndex)
				ip, _ = netInterfaceToIP16(intf)
			}
			copy(pi.Addr[:], ip)
		}
		if cm.IfIndex > 0 {
			pi.setIfindex(cm.IfIndex)
		}
	}
	return m.Next(sizeofInet6Pktinfo)
}

func parsePacketInfo(cm *ControlMessage, b []byte) {
	pi := (*inet6Pktinfo)(unsafe.Pointer(&b[0]))
	if len(cm.Dst) < net.IPv6len {
		cm.Dst = make(net.IP, net.IPv6len)
	}
	copy(cm.Dst, pi.Addr[:])
	cm.IfIndex = int(pi.Ifindex)
}
