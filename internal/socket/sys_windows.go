// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func probeProtocolStack() int {
	var p uintptr
	return int(unsafe.Sizeof(p))
}

const (
	sysAF_UNSPEC = windows.AF_UNSPEC
	sysAF_INET   = windows.AF_INET
	sysAF_INET6  = windows.AF_INET6

	sysSOCK_RAW = windows.SOCK_RAW

	sizeofSockaddrInet4 = 0x10
	sizeofSockaddrInet6 = 0x1c
)

func getsockopt(s uintptr, level, name int, b []byte) (int, error) {
	l := uint32(len(b))
	err := syscall.Getsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), (*int32)(unsafe.Pointer(&l)))
	return int(l), err
}

func setsockopt(s uintptr, level, name int, b []byte) error {
	return syscall.Setsockopt(syscall.Handle(s), int32(level), int32(name), (*byte)(unsafe.Pointer(&b[0])), int32(len(b)))
}

func recvmsg(s uintptr, buffers [][]byte, oob []byte, flags int, network string) (n, oobn int, recvflags int, from net.Addr, err error) {
	var h msghdr
	vs := make([]iovec, len(buffers))
	var sa []byte
	if network != "tcp" {
		sa = make([]byte, sizeofSockaddrInet6)
	}
	h.pack(vs, buffers, oob, sa)

	var bytesReceived uint32
	msg := (*windows.WSAMsg)(&h)
	msg.Flags = uint32(flags)
	controlLen := msg.Control.Len
	err = windows.SetsockoptInt(windows.Handle(s), windows.SOL_SOCKET, windows.SO_RCVTIMEO, 500)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	err = windows.WSARecvMsg(windows.Handle(s), msg, &bytesReceived, nil, nil)
	if err == windows.WSAEMSGSIZE && (msg.Flags&windows.MSG_CTRUNC) != 0 {
		// On windows, EMSGSIZE is raised in addition to MSG_CTRUNC, and
		// the original untruncated length of the control data is returned.
		// We reset the length back to the truncated portion which was received,
		// so the caller doesn't try to go out of bounds.
		// We also ignore the EMSGSIZE to emulate behavior of other platforms.
		msg.Control.Len = controlLen
		err = nil
	}
	if err == windows.WSAETIMEDOUT {
		err = syscall.EAGAIN
		return
	}
	if network != "tcp" {
		from, err = parseInetAddr(sa[:], network)
		if err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return int(bytesReceived), h.controllen(), h.flags(), from, err
}

func sendmsg(s uintptr, buffers [][]byte, oob []byte, to net.Addr, flags int) (int, error) {
	var h msghdr
	vs := make([]iovec, len(buffers))
	var sa []byte
	if to != nil {
		var a [sizeofSockaddrInet6]byte
		n := marshalInetAddr(to, a[:])
		sa = a[:n]
	}
	h.pack(vs, buffers, oob, sa)
	var bytesSent uint32
	err := windows.WSASendMsg(windows.Handle(s), (*windows.WSAMsg)(&h), uint32(flags), &bytesSent, nil, nil)
	return int(bytesSent), err
}

func recvmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}

func sendmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	return 0, errNotImplemented
}
