//go:build windows

package client

import (
	"fmt"
	"net"
	"os/user"

	"github.com/Microsoft/go-winio"
)

func pipeName() string {
	u, err := user.Current()
	if err != nil {
		return `\\.\pipe\passerelle`
	}
	return `\\.\pipe\passerelle-` + u.Uid
}

func dialIPC(socket string) (net.Conn, error) {
	if socket == "" || socket == SocketPath() {
		socket = pipeName()
	}
	return winio.DialPipe(socket, nil)
}

func listenIPC(socket string) (net.Listener, error) {
	if socket == "" || socket == SocketPath() {
		socket = pipeName()
	}
	sd := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"
	ln, err := winio.ListenPipe(socket, &winio.PipeConfig{
		SecurityDescriptor: sd,
		MessageMode:        false,
	})
	if err != nil {
		return nil, fmt.Errorf("named pipe: %w", err)
	}
	return ln, nil
}
