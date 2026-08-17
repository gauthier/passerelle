package protocol_test

import (
	"bytes"
	"testing"

	"github.com/gauthier/passerelle/protocol"
	controlv1 "github.com/gauthier/passerelle/protocol/controlv1"
)

func TestDeviceURIRoundTrip(t *testing.T) {
	uri := protocol.DeviceURI("alice", "dev_01")
	u, c, err := protocol.ParseDeviceURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u != "alice" || c != "dev_01" {
		t.Fatalf("got %s %s", u, c)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	env := &controlv1.Envelope{Seq: 7, Payload: &controlv1.Envelope_Hello{Hello: &controlv1.Hello{ProtocolMin: 1, ProtocolMax: 1}}}
	if err := protocol.WriteMessage(&buf, env); err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ReadMessage(&buf, protocol.MaxControlMessage, func() *controlv1.Envelope { return &controlv1.Envelope{} })
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 7 || got.GetHello().GetProtocolMax() != 1 {
		t.Fatalf("bad decode: %+v", got)
	}
}

func TestRejectOversizedFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	_, err := protocol.ReadMessage(&buf, 1024, func() *controlv1.Envelope { return &controlv1.Envelope{} })
	if err == nil {
		t.Fatal("expected error")
	}
}
