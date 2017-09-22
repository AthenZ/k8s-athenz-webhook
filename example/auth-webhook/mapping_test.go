package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"reflect"
	"strings"
	"testing"
	"time"

	"os"

	"fmt"
	"io/ioutil"

	api "github.com/yahoo/k8s-athenz-webhook"
	authn "k8s.io/api/authentication/v1beta1"
	authz "k8s.io/api/authorization/v1beta1"
)

var testContext = context.Background()

func TestMapReadAccess(t *testing.T) {
	expect := func(s string, v bool) {
		a := isReadAccess(s)
		if a != v {
			t.Errorf("read access check for %q: got %v, want %v", s, v, a)
		}
	}
	expect("get", true)
	expect("list", true)
	expect("watch", true)
	expect("read", false)
	expect("write", false)
	expect("frobnicate", false)
}

func TestMapSystemNs(t *testing.T) {
	expect := func(s string, v bool) {
		a := isSystemNamespace(s)
		if a != v {
			t.Errorf("system namespace check for %q: got %v, want %v", s, v, a)
		}
	}
	expect("kube-system", true)
	expect("kube-application", true)
	expect("kubedns", false)
	expect("something-different", false)
	expect("app-kube-systenm", false)
}

func TestMapUserMapping(t *testing.T) {
	m := &UserMapper{Groups: []string{"foo"}}
	u, err := m.MapUser(testContext, api.AthenzPrincipal{
		Domain:  "my.domain",
		Service: "my-service",
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := authn.UserInfo{
		Username: "my.domain.my-service",
		UID:      "my.domain.my-service",
		Groups:   []string{"foo"},
	}
	if !reflect.DeepEqual(expected, u) {
		t.Fatal("bad user info, want", expected, "got", u)
	}
}

func TestMapInList(t *testing.T) {
	tests := []struct {
		check   string
		list    []string
		outcome bool
	}{
		{"apples", nil, false},
		{"apples", []string{}, false},
		{"apples", []string{"oranges", "peaches"}, false},
		{"apples", []string{"oranges", "peaches", "apples"}, true},
	}
	for _, test := range tests {
		a := inList(test.check, test.list)
		if a != test.outcome {
			t.Errorf("inList %q -> %s, expected %v got %v", test.check, test.list, test.outcome, a)
		}
	}
}

func TestMapRestoreDomainName(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"foobarbaz", "foobarbaz"},
		{"foo-bar-baz", "foo.bar.baz"},
		{"foo-bar--baz", "foo.bar-baz"},
	}
	for _, test := range tests {
		a := RestoreDomainName(test.input)
		if a != test.output {
			t.Errorf("TestRestoreDomainName %q -> %q, got %q", test.input, test.output, a)
		}
	}
}

func TestDomainFromNamespace(t *testing.T) {
	adminDomain := "k8s.admin"
	d := &ResourceMapper{AdminDomain: adminDomain}
	tests := []struct {
		input  string
		output string
	}{
		{"", "k8s.admin"},                                                  // blank to admin
		{"foo-bar-baz", "foo.bar.baz"},                                     // dashes to dots
		{"kube-system-foo", "k8s.admin.kube-system-foo"},                   // dub-dashes to dash
		{"kube-system-foo-bar--baz", "k8s.admin.kube-system-foo-bar--baz"}, // no mods here
	}
	for _, test := range tests {
		a := d.DomainFromNamespace(test.input)
		if a != test.output {
			t.Errorf("DomainFromNamespace %q -> %q, got %q", test.input, test.output, a)
		}
	}
}

func TestMapPrincipalFromUser(t *testing.T) {
	adminDomain := "k8s.admin"
	d := &ResourceMapper{AdminDomain: adminDomain}
	tests := []struct {
		input  string
		output string
	}{
		{"foobar", "foobar"},                                                                // simple as is
		{"exotic:user", "exotic:user"},                                                      // exotic as-is
		{"system:anonymous", "system:anonymous"},                                            // this, in particular, should not be modified
		{"system:serviceaccount:foo", "system:serviceaccount:foo"},                          // single name doesn't change
		{"system:serviceaccount:foo:bar", "foo.bar"},                                        // 2 parts do
		{"system:serviceaccount:foo:bar:baz", "foo.bar"},                                    // third part ignored
		{"system:serviceaccount:kube-system-foo:bar", adminDomain + ".kube-system-foo.bar"}, // system domain
	}
	for _, test := range tests {
		a := d.PrincipalFromUser(test.input)
		if a != test.output {
			t.Errorf("PrincipalFromUser %q -> %q, got %q", test.input, test.output, a)
		}
	}
}

type result struct {
	principal string
	checks    []api.AthenzAccessCheck
	err       string
}

func TestMapResourceMapper(t *testing.T) {
	r := &ResourceMapper{
		AdminDomain:    "k8s",
		DenyResources:  []string{"pids"},
		AdminResources: []string{"namespaces"},
		DenyUsers:      []string{"system:anonymous"},
	}
	resourceSAR := func(user string, verb, ns, res, subres, name string) authz.SubjectAccessReviewSpec {
		return authz.SubjectAccessReviewSpec{
			User: user,
			ResourceAttributes: &authz.ResourceAttributes{
				Verb:        verb,
				Namespace:   ns,
				Resource:    res,
				Subresource: subres,
				Name:        name,
			},
		}
	}
	noresSAR := func(user string, verb, path string) authz.SubjectAccessReviewSpec {
		return authz.SubjectAccessReviewSpec{
			User: user,
			NonResourceAttributes: &authz.NonResourceAttributes{
				Verb: verb,
				Path: path,
			},
		}
	}
	makeChecks := func(p string, err string, action string, resources ...string) result {
		checks := []api.AthenzAccessCheck{}
		for _, r := range resources {
			checks = append(checks, api.AthenzAccessCheck{Action: action, Resource: r})
		}
		return result{
			principal: p,
			err:       err,
			checks:    checks,
		}
	}
	tests := []struct {
		input  authz.SubjectAccessReviewSpec
		output result
	}{
		{
			resourceSAR("bob", "write", "foo-bar", "things", "", ""),
			makeChecks("bob", "", "write", "foo.bar:things"),
		},
		{
			resourceSAR("bob", "write", "foo-bar", "things", "games", "monopoly"),
			makeChecks("bob", "", "write", "foo.bar:things.games"),
		},
		{
			noresSAR("bob", "write", "foo-bar"),
			makeChecks("bob", "", "write", "k8s:foo-bar"),
		},
		{
			resourceSAR("bob", "write", "foo-bar", "pids", "", ""),
			makeChecks("bob", "'pids' resources are not allowed through Athenz", ""),
		},
		{
			resourceSAR("system:anonymous", "write", "foo-bar", "things", "games", "monopoly"),
			makeChecks("system:anonymous", "'system:anonymous' is not authorized for any actions", ""),
		},
		{
			resourceSAR("bob", "write", "foo-bar", "namespaces", "", ""),
			makeChecks("bob", "", "write", "k8s:foo.bar.namespaces"),
		},
		{
			resourceSAR("bob", "list", "foo-bar", "namespaces", "", ""),
			makeChecks("bob", "", "list", "foo.bar:namespaces", "k8s:namespaces"),
		},
	}

	for i, test := range tests {
		p, checks, err := r.MapResource(testContext, test.input)
		switch {
		case err == nil && test.output.err == "": // ok
		case err != nil && test.output.err != "": //maybe ok
			if !strings.Contains(err.Error(), test.output.err) {
				t.Fatalf("Resource mapper %d: error: expected '%s' to contain '%s'", i, err.Error(), test.output.err)
			}
		default: // definitely not ok
			t.Fatalf("Resource mapper %d: err mismatch, want '%s' got %v", i, test.output.err, err)
		}
		if err == nil {
			actual := result{principal: p, checks: checks}
			if !reflect.DeepEqual(actual, test.output) {
				t.Errorf("Resource mapper %d: check mismatch want %v got %v", i, test.output, actual)
			}
		}
	}
}

func TestMapLogProvider(t *testing.T) {
	var buf bytes.Buffer
	lp := NewLogProvider(&buf)
	logger := lp("foobar")
	logger.Println("hello", "world")
	log := buf.String()
	contents := []string{"[foobar] ", "hello world"}
	for _, c := range contents {
		if !strings.Contains(log, c) {
			t.Errorf("log '%s' did not contain '%s'", log, c)
		}
	}
}

func randomSig() string {
	sig := "unknown"
	b := make([]byte, 5)
	_, err := rand.Reader.Read(b)
	if err == nil {
		sig = strings.ToLower(base32.StdEncoding.EncodeToString(b))
	}
	return sig
}

func newToken() string {
	return fmt.Sprintf("d=my.domain;n=my-service;e=%d;s=%s", time.Now().Unix(), randomSig())
}

func TestMapToken(t *testing.T) {
	file := "/tmp/token"
	s1 := newToken()
	err := ioutil.WriteFile(file, []byte(s1), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	ft, err := NewFileToken(file, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ft.Close()
	s, err := ft.TokenValue()
	if err != nil {
		t.Fatal(err)
	}
	if s != s1 {
		t.Errorf("bad token want %q got %q", s1, s)
	}
	s2 := newToken()
	err = ioutil.WriteFile(file, []byte(s2), 0644)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second + 100*time.Millisecond)
	s, err = ft.TokenValue()
	if err != nil {
		t.Fatal(err)
	}
	if s != s2 {
		t.Errorf("bad token want %q got %q", s2, s)
	}
}

func TestMapTokenImmediateError(t *testing.T) {
	file := "/tmp/token"
	err := ioutil.WriteFile(file, []byte("random"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	_, err = NewFileToken(file, true, time.Second)
	if err == nil {
		t.Fatal("expected error but succeeded")
	}
	msg := "invalid server identity token"
	if !strings.Contains(err.Error(), msg) {
		t.Fatalf("bad error message, %v, did not have %q", err, msg)
	}
}

func TestMapTokenDeferredError(t *testing.T) {
	file := "/tmp/token"
	s1 := newToken()
	err := ioutil.WriteFile(file, []byte(s1), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	ft, err := NewFileToken(file, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ft.Close()
	os.Remove(file)
	time.Sleep(time.Second + 100*time.Millisecond)
	_, err = ft.TokenValue()
	if err == nil {
		t.Fatal("expected token error, but succeeded")
	}
}

func TestMapTokenNoRefresh(t *testing.T) {
	file := "/tmp/token"
	s1 := newToken()
	err := ioutil.WriteFile(file, []byte(s1), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	ft, err := NewFileToken(file, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ft.Close()
	os.Remove(file)
	time.Sleep(time.Second + 100*time.Millisecond)
	_, err = ft.TokenValue()
	if err != nil {
		t.Fatal(err)
	}
}
