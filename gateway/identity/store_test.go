package identity_test

import (
	"testing"
	"time"

	"github.com/gauthier/passerelle/gateway/identity"
	"github.com/gauthier/passerelle/internal/tlsutil"
)

func TestEnrollAndRevoke(t *testing.T) {
	dir := t.TempDir()
	st, err := identity.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser("bob", identity.DefaultQuotas()); err != nil {
		t.Fatal(err)
	}
	tok, err := st.CreateToken("bob", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.ConsumeToken(tok)
	if err != nil || user != "bob" {
		t.Fatalf("%s %v", user, err)
	}
	if _, err := st.ConsumeToken(tok); err == nil {
		t.Fatal("token replay")
	}
	csr, _, err := tlsutil.CreateCSR()
	if err != nil {
		t.Fatal(err)
	}
	cert, clientID, _, err := st.Enroll("bob", string(csr))
	if err != nil || cert == nil || clientID == "" {
		t.Fatalf("%v %s", err, clientID)
	}
	if err := st.CheckDevice("bob", clientID, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice(clientID); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckDevice("bob", clientID, ""); err == nil {
		t.Fatal("expected revoked")
	}
}

func TestPatchUserQuotas(t *testing.T) {
	dir := t.TempDir()
	st, err := identity.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser("bob", identity.DefaultQuotas()); err != nil {
		t.Fatal(err)
	}
	devices := 2
	u, err := st.PatchUserQuotas("bob", identity.QuotaPatch{MaxDevices: &devices})
	if err != nil {
		t.Fatal(err)
	}
	if u.Quotas.MaxDevices != 2 || u.Quotas.MaxTunnels != 10 || u.Quotas.MaxConns != 100 {
		t.Fatalf("%+v", u.Quotas)
	}
	got, err := st.User("bob")
	if err != nil || got.Quotas.MaxDevices != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	zero := 0
	if _, err := st.PatchUserQuotas("bob", identity.QuotaPatch{MaxTunnels: &zero}); err == nil {
		t.Fatal("expected invalid tunnels")
	}
}
