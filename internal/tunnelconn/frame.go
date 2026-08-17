package tunnelconn

import (
	"io"

	"github.com/gauthier/passerelle/protocol"
	controlv1 "github.com/gauthier/passerelle/protocol/controlv1"
)

func WritePreamble(w io.Writer, tunnelID string) error {
	return protocol.WriteMessage(w, &controlv1.DataPreamble{TunnelId: tunnelID})
}

func ReadPreamble(r io.Reader) (string, error) {
	msg, err := protocol.ReadMessage(r, protocol.MaxPreamble, func() *controlv1.DataPreamble {
		return &controlv1.DataPreamble{}
	})
	if err != nil {
		return "", err
	}
	return msg.GetTunnelId(), nil
}

func ReadEnvelope(r io.Reader) (*controlv1.Envelope, error) {
	return protocol.ReadMessage(r, protocol.MaxControlMessage, func() *controlv1.Envelope {
		return &controlv1.Envelope{}
	})
}

func WriteEnvelope(w io.Writer, env *controlv1.Envelope) error {
	return protocol.WriteMessage(w, env)
}
