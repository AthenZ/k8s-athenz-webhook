package webhook

import (
	"context"
	"errors"
	"testing"

	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
)

func TestAPIAccessCheckString(t *testing.T) {
	a := &AthenzAccessCheck{Action: "grok", Resource: "my.domain:server"}
	expected := "grok on my.domain:server"
	if expected != a.String() {
		t.Error("want", expected, "got", a.String())
	}
}

func TestAPIConfigDefaults(t *testing.T) {
	c := &Config{}
	c.initDefaults()
	if c.LogProvider == nil {
		t.Error("log provider not initialized")
	}
	if c.Timeout == 0 {
		t.Error("timeout not initialized")
	}
	l := c.LogProvider("foobar")
	if l == nil {
		t.Error("log provider did not return logger")
	}
}

func ensurePanic(t *testing.T, fn func()) {
	defer func() {
		if r := recover(); r != nil {
		} else {
			t.Fatal("func did not panic")
		}
	}()
	fn()
}

type urm struct {
}

func (u *urm) MapUser(ctx context.Context, domain, service string) (authn.UserInfo, error) {
	return authn.UserInfo{}, errors.New("not implemented")
}

func (u *urm) MapResource(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
	return "", nil, errors.New("not implemented")
}

func TestAPINewAuthenticator(t *testing.T) {
	h := NewAuthenticator(AuthenticationConfig{
		Mapper: &urm{},
	})
	if h == nil {
		t.Fatal("authenticator was nil")
	}
	ensurePanic(t, func() {
		NewAuthenticator(AuthenticationConfig{})
	})
}

func TestAPINewAuthorizer(t *testing.T) {
	h := NewAuthorizer(AuthorizationConfig{
		Mapper: &urm{},
	})
	if h == nil {
		t.Fatal("authorizer was nil")
	}
	ensurePanic(t, func() {
		NewAuthorizer(AuthorizationConfig{})
	})
}
