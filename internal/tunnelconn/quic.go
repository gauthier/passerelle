package tunnelconn

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/gauthier/passerelle/protocol"
	"github.com/quic-go/quic-go"
)

func QUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  45 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		Allow0RTT:       false,
		EnableDatagrams: false,
	}
}

func ListenQUIC(udp net.PacketConn, tlsConf *tls.Config) (*quic.Listener, error) {
	tc := tlsConf.Clone()
	tc.NextProtos = []string{protocol.ALPN}
	tc.MinVersion = tls.VersionTLS13
	return quic.Listen(udp, tc, QUICConfig())
}

func DialQUIC(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	tc := tlsConf.Clone()
	tc.NextProtos = []string{protocol.ALPN}
	tc.MinVersion = tls.VersionTLS13
	return quic.DialAddr(ctx, addr, tc, QUICConfig())
}
