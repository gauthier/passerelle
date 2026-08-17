package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"

	"github.com/gauthier/passerelle/internal/tlsutil"
	"github.com/gauthier/passerelle/internal/tunnelconn"
	"github.com/quic-go/quic-go"
)

type Stream = tunnelconn.Stream

type Session struct {
	id       string
	userID   string
	clientID string
	opened   atomic.Int64
	control  Stream
	openData func(ctx context.Context) (Stream, error)
	close    func() error
}

func (s *Session) ID() string       { return s.id }
func (s *Session) UserID() string   { return s.userID }
func (s *Session) ClientID() string { return s.clientID }
func (s *Session) Control() Stream  { return s.control }

func (s *Session) OpenDataStream() (Stream, error) {
	s.opened.Add(1)
	return s.openData(context.Background())
}

func (s *Session) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

func IdentityFromTLS(state tls.ConnectionState) (string, string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", "", errors.New("missing client certificate")
	}
	return tlsutil.IdentityFromCert(state.PeerCertificates[0])
}

func FromQUIC(ctx context.Context, conn *quic.Conn) (*Session, error) {
	st := conn.ConnectionState().TLS
	userID, clientID, err := IdentityFromTLS(st)
	if err != nil {
		_ = conn.CloseWithError(1, "unauthorized")
		return nil, err
	}
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Session{
		id:       clientID,
		userID:   userID,
		clientID: clientID,
		control:  ctrl,
		openData: func(ctx context.Context) (Stream, error) {
			return conn.OpenStreamSync(ctx)
		},
		close: func() error { return conn.CloseWithError(0, "closed") },
	}, nil
}

func FromH2(ctx context.Context, gc *tunnelconn.H2GatewayConn, userID, clientID string) (*Session, error) {
	ctrl, err := gc.OpenControl(ctx)
	if err != nil {
		return nil, err
	}
	return &Session{
		id:       clientID,
		userID:   userID,
		clientID: clientID,
		control:  ctrl,
		openData: gc.OpenData,
		close:    gc.Close,
	}, nil
}
