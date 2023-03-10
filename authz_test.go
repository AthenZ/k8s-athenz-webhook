package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var helpText = "help me!"

func TestAuthzError(t *testing.T) {
	e := NewAuthzError(errors.New("foobar"), "this is bad")
	if e.Reason() != "this is bad" {
		t.Error("bad reason", e.reason)
	}
	if e.Error() != "foobar" {
		t.Error("bad error", e.Error())
	}
}

type mrfn func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error)

func (m mrfn) MapResource(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
	return m(ctx, spec)
}

type authzScaffold struct {
	*mockZMS
	t      *testing.T
	l      *lp
	config AuthorizationConfig
}

func (a *authzScaffold) resetLog() {
	a.l.b.Reset()
}

func (a *authzScaffold) containsLog(s string) {
	log := a.l.b.String()
	if !strings.Contains(log, s) {
		a.t.Errorf("log '%s' did not contain '%s'", log, s)
	}
}

func newAuthzScaffold(t *testing.T) *authzScaffold {
	m := newMockZMS()
	l, p := logProvider()
	fixedToken := stdToken()
	c := AuthorizationConfig{
		Config: Config{
			AuthHeader:  "X-Auth",
			ZMSEndpoint: m.URL,
			ZTSEndpoint: m.URL,
			Timeout:     200 * time.Millisecond,
			LogProvider: p,
		},
		HelpMessage: helpText,
		Token: func() (string, error) {
			return fixedToken.String(), nil
		},
		Mapper: mrfn(func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
			return "std.principal",
				[]AthenzAccessCheck{{Action: "frob-athenz", Resource: "my.domain:knob"}},
				nil
		}),
	}
	return &authzScaffold{
		t:       t,
		mockZMS: m,
		l:       l,
		config:  c,
	}
}

func newAuthzScaffoldX509(t *testing.T) *authzScaffold {
	m := newMockZMS()
	l, p := logProvider()
	c := AuthorizationConfig{
		Config: Config{
			AuthHeader:  "X-Auth",
			ZMSEndpoint: m.URL,
			Timeout:     200 * time.Millisecond,
			LogProvider: p,
		},
		HelpMessage: helpText,
		AthenzX509: func() (*tls.Config, error) {
			return &tls.Config{}, nil
		},
		AthenzClientAuthnx509Mode: true,
		Mapper: mrfn(func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
			return "std.principal",
				[]AthenzAccessCheck{{Action: "frob-athenz", Resource: "my.domain:knob"}},
				nil
		}),
	}
	return &authzScaffold{
		t:       t,
		mockZMS: m,
		l:       l,
		config:  c,
	}
}

func stdAuthzInput() authz.SubjectAccessReview {
	return authz.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       authzSupportedKind,
			APIVersion: authzSupportedVersion,
		},
		Spec: authz.SubjectAccessReviewSpec{
			User: "bob",
			ResourceAttributes: &authz.ResourceAttributes{
				Namespace: "foo-bar",
				Verb:      "get",
				Resource:  "baz",
			},
		},
	}
}

type authzTestResult struct {
	w    *httptest.ResponseRecorder
	body *bytes.Buffer
}

func runAuthzTest(s *authzScaffold, input []byte, handler http.Handler) *authzTestResult {
	s.resetLog()
	az := NewAuthorizer(s.config)
	w := httptest.NewRecorder()
	var respBody bytes.Buffer
	w.Body = &respBody
	r := httptest.NewRequest("POST", "/authz", bytes.NewBuffer(input))
	s.h = handler
	az.ServeHTTP(w, r)
	return &authzTestResult{
		w:    w,
		body: &respBody,
	}
}

func checkGrant(t *testing.T, body []byte, expected bool) authz.SubjectAccessReview {
	var tr authz.SubjectAccessReview
	err := json.Unmarshal(body, &tr)
	if err != nil {
		t.Fatalf("bad response '%s', %v", body, err)
	}
	if tr.Status.Allowed != expected {
		t.Fatalf("bad grant, want %v got %v", expected, tr.Status.Allowed)
	}
	return tr
}

func TestAuthzHappyPath(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	var tokenReceived, urlPath string
	grant := struct {
		Granted bool `json:"granted"`
	}{true}
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenReceived = r.Header.Get("X-Auth")
		urlPath = r.URL.Path
		writeJSON(testContext, w, grant)
	})
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), zmsHandler)
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	expectedToken, _ := s.config.Token()
	if tokenReceived != expectedToken {
		t.Errorf("token not sent, want '%s' got '%s'", expectedToken, tokenReceived)
	}
	if urlPath != "/access/frob-athenz/my.domain:knob" {
		t.Error("invalid ZMS URL path", urlPath)
	}
	tr := checkGrant(t, body.Bytes(), true)
	if tr.Kind != input.Kind {
		t.Error("invalid Kind", tr.Kind)
	}
	if tr.APIVersion != input.APIVersion {
		t.Error("invalid API version", tr.APIVersion)
	}
	s.containsLog("authz granted bob: get on foo-bar:baz:: -> via frob-athenz on my.domain:knob")
}

func TestAuthzHappyPathX509(t *testing.T) {
	s := newAuthzScaffoldX509(t)
	s.config.LogFlags = LogTraceAthenz | LogTraceServer
	defer s.Close()
	var urlPath string
	grant := struct {
		Granted bool `json:"granted"`
	}{true}
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath = r.URL.Path
		writeJSON(testContext, w, grant)
	})
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), zmsHandler)
	w := ar.w
	body := ar.body
	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	if urlPath != "/access/frob-athenz/my.domain:knob" {
		t.Error("invalid ZMS URL path", urlPath)
	}
	tr := checkGrant(t, body.Bytes(), true)
	if tr.Kind != input.Kind {
		t.Error("invalid Kind", tr.Kind)
	}
	if tr.APIVersion != input.APIVersion {
		t.Error("invalid API version", tr.APIVersion)
	}
	s.containsLog("authz granted bob: get on foo-bar:baz:: -> via frob-athenz on my.domain:knob")
}

func TestAuthzZMSReject(t *testing.T) {

	tests := []struct {
		name string
		s    interface{}
	}{
		{"token", newAuthnScaffold(t)},
		{"x509", newAuthzScaffoldX509(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newAuthzScaffold(t)
			defer s.Close()
			grant := struct {
				Granted bool `json:"granted"`
			}{false}
			zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(testContext, w, grant)
			})
			input := stdAuthzInput()
			ar := runAuthzTest(s, serialize(input), zmsHandler)
			w := ar.w
			body := ar.body

			if w.Result().StatusCode != 200 {
				t.Fatal("invalid status code", w.Result().StatusCode)
			}
			tr := checkGrant(t, body.Bytes(), false)
			if tr.Status.EvaluationError == "" {
				t.Error("eval error not set")
			}
			if tr.Status.Reason != "" {
				t.Error("authz internals leak")
			}
			s.containsLog("authz denied bob: get on foo-bar:baz:: -> error:principal std.principal does not have access to any of 'frob-athenz on my.domain:knob' resources")
		})
	}
}

func TestAuthzMapperBypass(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	s.config.Mapper = mrfn(func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
		return "std.principal",
			nil,
			nil
	})
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), nil)
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	checkGrant(t, body.Bytes(), true)
	s.containsLog("no Athenz resource checks needed")
}

func TestAuthzMapperError(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	s.config.Mapper = mrfn(func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
		return "",
			nil,
			errors.New("foobar")
	})
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), nil)
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	msg := "mapping error: foobar"
	if tr.Status.EvaluationError != msg {
		t.Errorf("want '%s', got '%s'", msg, tr.Status.EvaluationError)
	}
	if tr.Status.Reason != helpText {
		t.Error("authz internals leak")
	}
	s.containsLog(msg)
}

func TestAuthzTokenErrors(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	s.config.Token = func() (string, error) {
		return "", fmt.Errorf("no token for you")
	}
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), nil)
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	msg := "no token for you"
	if tr.Status.EvaluationError != msg {
		t.Errorf("want '%s', got '%s'", msg, tr.Status.EvaluationError)
	}
	reason := "internal setup error." + helpText
	if tr.Status.Reason != reason {
		t.Errorf("reason mismatch: want '%s', got'%s'", reason, tr.Status.Reason)
	}
	s.containsLog(msg)
}

func TestAuthzBadToken(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	reason := "internal setup error." + helpText
	if tr.Status.Reason != reason {
		t.Errorf("reason mismatch: want '%s', got'%s'", reason, tr.Status.Reason)
	}
	s.containsLog("returned 401")
}

func TestAuthzAthenz400(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	reason := "Invalid ResourceName error."
	if tr.Status.Reason != reason {
		t.Errorf("reason mismatch: want '%s', got'%s'", reason, tr.Status.Reason)
	}
	s.containsLog("returned 400")
	s.containsLog("authz denied bob: get on foo-bar:baz:: -> error:resource related error for frob-athenz on my.domain:knob")
}

func TestAuthzAthenz404(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()
	input := stdAuthzInput()
	ar := runAuthzTest(s, serialize(input), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	reason := "" // Continue to the the next check
	if tr.Status.Reason != reason {
		t.Errorf("reason mismatch: want '%s', got'%s'", reason, tr.Status.Reason)
	}
	s.containsLog("authz denied bob: get on foo-bar:baz:: -> error:principal std.principal does not have access to any of 'frob-athenz on my.domain:knob' resources")
}

func TestAuthzAthenz500(t *testing.T) {
	s := newAuthzScaffold(t)
	s.config.LogFlags = LogTraceAthenz | LogTraceServer
	defer s.Close()
	input := stdAuthzInput()
	input.Spec.ResourceAttributes = nil
	input.Spec.NonResourceAttributes = &authz.NonResourceAttributes{
		Path: "/foo",
		Verb: "get",
	}
	ar := runAuthzTest(s, serialize(input), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	w := ar.w
	body := ar.body

	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)
	if tr.Status.Reason != helpText {
		t.Errorf("reason mismatch: want '%s', got'%s'", helpText, tr.Status.Reason)
	}
	s.containsLog("returned 500")
	s.containsLog("authz denied bob: get on /foo") // non-resource attrs should be printed
	// test debug output
	// t.Log(s.l.b.String())
	for _, line := range []string{
		"POST /authz",
		"request body: {",
		"response status: 500",
	} {
		s.containsLog(line)
	}
}

func TestAuthzBadInputs(t *testing.T) {
	s := newAuthzScaffold(t)
	defer s.Close()

	base := stdAuthzInput()
	badKind := func() []byte {
		c := base
		c.Kind = "foo"
		return serialize(c)
	}
	badVersion := func() []byte {
		c := base
		c.APIVersion = "foo"
		return serialize(c)
	}
	emptyStruct := func() []byte {
		c := base
		c.Spec.ResourceAttributes = nil
		c.Spec.NonResourceAttributes = nil
		return serialize(c)
	}

	tests := []struct {
		code  int
		input []byte
		msg   string
	}{
		{400, nil, "empty body for authorization request"},
		{400, badKind(), "unsupported authorization kind, want 'SubjectAccessReview', got 'foo'"},
		{400, badVersion(), "unsupported authorization version, want 'authorization.k8s.io/v1', got 'foo'"},
		{400, emptyStruct(), "bad authorization spec, must have one of resource or non-resource attributes"},
		{400, append(serialize(base), 'X'), "invalid JSON request"},
	}
	for _, test := range tests {
		ar := runAuthzTest(s, test.input, nil)
		if ar.w.Code != test.code {
			t.Fatalf("test %q: unexpected status code want %d, got %d", test.msg, test.code, ar.w.Code)
		}
		switch test.code {
		case 200:
		default:
			if !strings.Contains(ar.body.String(), test.msg) {
				t.Errorf("response '%s' did not contain '%s'", ar.body.String(), test.msg)
			}
		}
	}
}

func TestUseCacheEval(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()
	crMap, err := c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	c.domainMap["home.domain"] = crMap
	s := newAuthzScaffold(t)
	s.config.Cache = c
	az := newAuthz(s.config)
	log := s.config.LogProvider("test")
	checks := []AthenzAccessCheck{
		{
			Resource: "home.domain:pods",
			Action:   "get",
		},
	}
	res, err := az.useCacheEval(log, "user.name", checks)
	if err != nil {
		t.Error("Should not have error")
	}
	if res == nil {
		t.Error("Should return grantStatus true")
	}
}
