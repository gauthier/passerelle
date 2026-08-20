package router

import (
	"errors"
	"io"
	"testing"
	"time"
)

type fakeSess struct {
	user, client string
}

func (f *fakeSess) UserID() string   { return f.user }
func (f *fakeSess) ClientID() string { return f.client }
func (f *fakeSess) OpenDataStream() (io.ReadWriteCloser, error) {
	return nil, errors.New("no streams")
}

func TestReallocateAfterDisconnect(t *testing.T) {
	r := New("example.test", time.Minute)
	old := &fakeSess{user: "alice", client: "dev1"}
	alloc, err := r.Allocate(old, "lbe", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Lookup("lbe.example.test"); !ok {
		t.Fatal("expected live lookup")
	}

	r.DisconnectSession(old)
	if _, _, ok := r.Lookup("lbe.example.test"); ok {
		t.Fatal("lookup should fail while in grace")
	}

	newer := &fakeSess{user: "alice", client: "dev1"}
	alloc2, err := r.Allocate(newer, "lbe", false)
	if err != nil {
		t.Fatal(err)
	}
	if alloc2.Hostname != alloc.Hostname {
		t.Fatalf("hostname changed: %s -> %s", alloc.Hostname, alloc2.Hostname)
	}
	if _, sess, ok := r.Lookup("lbe.example.test"); !ok || sess != newer {
		t.Fatal("expected rebound lookup")
	}
}

func TestDisconnectSessionDoesNotTouchOtherSession(t *testing.T) {
	r := New("example.test", time.Minute)
	a := &fakeSess{user: "alice", client: "dev1"}
	b := &fakeSess{user: "alice", client: "dev1"}
	if _, err := r.Allocate(a, "one", false); err != nil {
		t.Fatal(err)
	}
	r.DisconnectSession(a)
	if _, err := r.Allocate(b, "one", false); err != nil {
		t.Fatal(err)
	}
	r.DisconnectSession(a) // stale close after replace
	if _, sess, ok := r.Lookup("one.example.test"); !ok || sess != b {
		t.Fatal("new session should still own the hostname")
	}
}
