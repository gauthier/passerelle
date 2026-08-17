package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

func WriteMessage(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxControlMessage {
		return fmt.Errorf("control message too large: %d", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func ReadMessage[T proto.Message](r io.Reader, max int, alloc func() T) (T, error) {
	var zero T
	if max <= 0 {
		max = MaxControlMessage
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return zero, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || int(n) > max {
		return zero, fmt.Errorf("invalid framed message length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return zero, err
	}
	msg := alloc()
	if err := proto.Unmarshal(buf, msg); err != nil {
		return zero, err
	}
	return msg, nil
}
