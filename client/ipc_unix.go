//go:build unix

package client

import (
	"net"
	"os"
	"path/filepath"
)

func dialIPC(socket string) (net.Conn, error) {
	return net.Dial("unix", socket)
}

func listenIPC(socket string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
