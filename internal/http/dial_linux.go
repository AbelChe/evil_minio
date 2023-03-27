//go:build linux
// +build linux

// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package http

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setTCPParameters(network, address string, c syscall.RawConn) error {
	c.Control(func(fdPtr uintptr) {
		// got socket file descriptor to set parameters.
		fd := int(fdPtr)

		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)

		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)

		// Enable TCP open
		// https://lwn.net/Articles/508865/ - 16k queue size.
		_ = syscall.SetsockoptInt(fd, syscall.SOL_TCP, unix.TCP_FASTOPEN, 16*1024)

		// Enable TCP fast connect
		// TCPFastOpenConnect sets the underlying socket to use
		// the TCP fast open connect. This feature is supported
		// since Linux 4.11.
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)

		// Enable TCP quick ACK, John Nagle says
		// "Set TCP_QUICKACK. If you find a case where that makes things worse, let me know."
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, unix.TCP_QUICKACK, 1)

		// The time (in seconds) the connection needs to remain idle before
		// TCP starts sending keepalive probes
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 15)

		// Number of probes.
		// ~ cat /proc/sys/net/ipv4/tcp_keepalive_probes (defaults to 9, we reduce it to 5)
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 5)

		// Wait time after successful probe in seconds.
		// ~ cat /proc/sys/net/ipv4/tcp_keepalive_intvl (defaults to 75 secs, we reduce it to 15 secs)
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 15)

		// Set tcp user timeout in addition to the keep-alive - tcp-keepalive is not enough to close a socket
		// with dead end because tcp-keepalive is not fired when there is data in the socket buffer.
		//    https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
		// This is a sensitive configuration, it is better to set it to high values, > 60 secs
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, (15+5*15)*1000)
	})
	return nil
}

// DialContext is a function to make custom Dial for internode communications
type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

// NewInternodeDialContext setups a custom dialer for internode communication
func NewInternodeDialContext(dialTimeout time.Duration) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: dialTimeout,
			Control: setTCPParameters,
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

// NewCustomDialContext setups a custom dialer for any external communication and proxies.
func NewCustomDialContext(dialTimeout time.Duration) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: dialTimeout,
			Control: setTCPParameters,
		}
		return dialer.DialContext(ctx, network, addr)
	}
}
