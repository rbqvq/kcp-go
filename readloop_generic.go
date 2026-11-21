// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

import (
	"github.com/pkg/errors"
	"github.com/xtaci/kcp-go/v5/internal/cmsg"
	libnetip "github.com/xtaci/kcp-go/v5/internal/lib/net/netip"
)

// readLoopGeneric is the standard procedure for reading from a connection
func (s *UDPSession) readLoopGeneric() {
	buf := make([]byte, maxPacketSize)

	for {
		n, remoteAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.notifyReadError(errors.WithStack(err))
			return
		}

		if s.isClosed() {
			return
		}

		if !isValidAddr(remoteAddr) {
			continue
		}

		// Ensure the packet comes from the same source.
		if !isSameAddr(remoteAddr, s.remoteAddr) {
			DefaultSnmp.increaseInErrs()
			continue
		}

		s.dispatch(buf[:n])
	}
}

// readLoopGeneric is the standard procedure for reading and accepting connections on a listener
func (l *Listener) readLoopGeneric() {
	buf := make([]byte, maxPacketSize)
	for {
		n, remoteAddr, err := l.conn.ReadFrom(buf)
		if err != nil {
			l.notifyReadError(errors.WithStack(err))
			return
		}

		if !isValidAddr(remoteAddr) {
			continue
		}

		l.dispatch(buf[:n], libnetip.AddrInterface{}, nil, remoteAddr)
	}
}

// readLoopGenericUDP is the standard procedure for reading and accepting connections on a listener
func (l *Listener) readLoopGenericUDP() {
	udpConn := l.conn.(udpConn)

	buf := make([]byte, maxPacketSize)
	for {
		n, _, _, remoteAddr, err := udpConn.ReadMsgUDP(buf, nil)
		if err != nil {
			l.notifyReadError(errors.WithStack(err))
			return
		}

		if remoteAddr == nil {
			continue
		}

		l.dispatch(buf[:n], libnetip.AddrInterface{}, nil, remoteAddr)
	}
}

// readLoopGenericUnspecified receives packets and their local destination addresses.
func (l *Listener) readLoopGenericUnspecified() {
	udpConn := l.conn.(udpConn)

	buf := make([]byte, maxPacketSize)
	oob := make([]byte, cmsgPacketSize)
	for {
		n, nn, _, remoteAddr, err := udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			l.notifyReadError(errors.WithStack(err))
			return
		}

		// The destination is required to select the reply source and session key.
		laddr, err := cmsg.ParseControlMessage(oob[:nn])
		if err != nil {
			continue
		}

		if !isUnicast(laddr.Addr()) {
			continue
		}

		localAddr := cmsg.ResolveUDPAddr(laddr, l.localPort)
		l.dispatch(buf[:n], laddr, localAddr, remoteAddr)
	}
}
