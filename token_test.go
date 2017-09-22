package webhook

import (
	"fmt"
	"testing"
	"time"
)

func TestTokenGood(t *testing.T) {
	ft := stdToken()
	st := ft.String()
	nt, err := newNToken(st)
	if err != nil {
		t.Fatal("errors on good token,", err)
	}
	err = nt.checkExpiry()
	if err != nil {
		t.Fatal("expiry error on good token,", err)
	}
	if nt.domain() != ft.domain {
		t.Error("want", ft.domain, "got", nt.domain())
	}
	if nt.name() != ft.name {
		t.Error("want", ft.name, "got", nt.name())
	}
	if nt.expiration.Unix() != ft.expiration.Unix() {
		t.Error("want", ft.expiration.Unix(), "got", nt.expiration.Unix())
	}
	if nt.signature() != ft.signature {
		t.Error("want", ft.signature, "got", nt.signature())
	}
	e := fmt.Sprintf("%s.%s", ft.domain, ft.name)
	if nt.String() != e {
		t.Error("want", e, "got", nt.String())
	}
}

func TestTokenIllFormed(t *testing.T) {
	tests := []struct {
		mod func(f *fakeToken)
		msg string
	}{
		{func(f *fakeToken) { f.domain = "" }, "no domain in token"},
		{func(f *fakeToken) { f.name = "" }, "no name in token"},
		{func(f *fakeToken) { f.signature = "" }, "no signature in token"},
	}
	for _, test := range tests {
		f := stdToken()
		test.mod(f)
		err := VerifyToken(f.String(), false)
		if err == nil {
			t.Fatalf("bad token was accepted: '%s', expected error with msg '%s'", f.String(), test.msg)
		}
		if err.Error() != test.msg {
			t.Errorf("bad msg want '%s', got '%s'", test.msg, err.Error())
		}
	}
	tok := stdToken().String() + ";garbage"
	_, err := newNToken(tok)
	msg := "bad field in token 'garbage'"
	if err == nil {
		t.Fatalf("bad token was accepted: '%s', expected error with msg '%s'", tok, msg)
	}
	if err.Error() != msg {
		t.Errorf("bad msg want '%s', got '%s'", msg, err.Error())
	}
}

func TestTokenExpiry(t *testing.T) {
	tests := []struct {
		mod func(f *fakeToken)
		msg string
	}{
		{func(f *fakeToken) { f.expireString = "xxx" }, "bad expiration in token, 'xxx'"},
		{func(f *fakeToken) { f.expiration = nil }, "no expiration in token"},
		{func(f *fakeToken) { x := time.Now().Add(-1 * time.Hour); f.expiration = &x }, "token has expired"},
	}
	for _, test := range tests {
		f := stdToken()
		test.mod(f)
		err := VerifyToken(f.String(), true)
		if err == nil {
			t.Fatalf("expire check succeeded, expected to fail with '%s'", test.msg)
		}
		if err.Error() != test.msg {
			t.Errorf("bad msg want '%s', got '%s'", test.msg, err.Error())
		}
	}

}
