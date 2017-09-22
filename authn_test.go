package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	authn "k8s.io/api/authentication/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mpfn func(ctx context.Context, p AthenzPrincipal) (authn.UserInfo, error)

func (m mpfn) MapUser(ctx context.Context, p AthenzPrincipal) (authn.UserInfo, error) {
	return m(ctx, p)
}

type authnScaffold struct {
	*mockZMS
	t      *testing.T
	l      *lp
	config AuthenticationConfig
	token  *fakeToken
}

func (a *authnScaffold) resetLog() {
	a.l.b.Reset()
}

func (a *authnScaffold) containsLog(s string) {
	log := a.l.b.String()
	if !strings.Contains(log, s) {
		a.t.Errorf("log '%s' did not contain '%s'", log, s)
	}
}

func newAuthnScaffold(t *testing.T) *authnScaffold {
	m := newMockZMS()
	l, p := logProvider()
	c := AuthenticationConfig{
		Config: Config{
			AuthHeader:  "X-Auth",
			Endpoint:    m.URL,
			Timeout:     200 * time.Millisecond,
			LogProvider: p,
		},
		Mapper: mpfn(func(ctx context.Context, p AthenzPrincipal) (authn.UserInfo, error) {
			return authn.UserInfo{
				Username: p.Domain + "." + p.Service,
				UID:      "100",
				Groups:   []string{"foo"},
			}, nil
		}),
	}
	return &authnScaffold{
		t:       t,
		mockZMS: m,
		l:       l,
		config:  c,
		token:   stdToken(),
	}
}

func stdAuthnInput(token string) authn.TokenReview {
	return authn.TokenReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       authnSupportedKind,
			APIVersion: authnSupportedVersion,
		},
		Spec: authn.TokenReviewSpec{
			Token: token,
		},
	}
}

type authnTestResult struct {
	w    *httptest.ResponseRecorder
	body *bytes.Buffer
}

func runAuthnTest(s *authnScaffold, input []byte, handler http.Handler) *authnTestResult {
	s.resetLog()
	an := NewAuthenticator(s.config)
	w := httptest.NewRecorder()
	var respBody bytes.Buffer
	w.Body = &respBody
	r := httptest.NewRequest("POST", "/authn", bytes.NewBuffer(input))
	s.h = handler
	an.ServeHTTP(w, r)
	return &authnTestResult{
		w:    w,
		body: &respBody,
	}
}

func TestAuthnHappyPath(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()
	input := stdAuthnInput(s.token.String())

	var urlPath, tokenReceived string
	ap := AthenzPrincipal{
		Domain:  "my.domain",
		Service: "foo",
		Token:   stdToken().String(),
	}
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenReceived = r.Header.Get("X-Auth")
		urlPath = r.URL.Path
		writeJSON(testContext, w, ap)
	})
	ar := runAuthnTest(s, serialize(input), zmsHandler)
	w := ar.w
	body := ar.body
	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	if tokenReceived != s.token.String() {
		t.Errorf("token not sent, want '%s' got '%s'", s.token.String(), tokenReceived)
	}
	if urlPath != "/principal" {
		t.Error("invalid ZMS URL path", urlPath)
	}
	var tr authn.TokenReview
	err := json.Unmarshal(body.Bytes(), &tr)
	if err != nil {
		t.Fatalf("bad response '%s', %v", body.Bytes(), err)
	}
	if tr.Kind != input.Kind {
		t.Error("invalid Kind", tr.Kind)
	}
	if tr.APIVersion != input.APIVersion {
		t.Error("invalid API version", tr.APIVersion)
	}
	expected := authn.UserInfo{
		Username: "my.domain.foo",
		UID:      "100",
		Groups:   []string{"foo"},
	}
	if !reflect.DeepEqual(expected, tr.Status.User) {
		t.Errorf("bad output, want %v got %v", expected, tr.Status.User)
	}
	s.containsLog("authn granted 'my.domain.my-name'")
	s.containsLog("-> user=my.domain.foo, uid=100, groups=[foo]")
}

func TestAuthnZMSReject(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()
	input := stdAuthnInput(s.token.String())
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := struct{ Message string }{"Forbidden"}
		w.WriteHeader(401)
		writeJSON(testContext, w, m)
	})
	ar := runAuthnTest(s, serialize(input), zmsHandler)
	w := ar.w
	body := ar.body
	if w.Result().StatusCode != 200 {
		t.Fatal("invalid status code", w.Result().StatusCode)
	}
	var tr authn.TokenReview
	err := json.Unmarshal(body.Bytes(), &tr)
	if err != nil {
		t.Fatalf("bad response '%s', %v", body.Bytes(), err)
	}
	if tr.Kind != input.Kind {
		t.Error("invalid Kind", tr.Kind)
	}
	if tr.APIVersion != input.APIVersion {
		t.Error("invalid API version", tr.APIVersion)
	}
	if tr.Status.Authenticated {
		t.Error("ZMS reject returned success auth!")
	}
	msg := "/principal returned 401 (Forbidden)"
	if !strings.Contains(tr.Status.Error, msg) {
		t.Errorf("status log '%s' did not contain '%s'", tr.Status.Error, msg)
	}
	s.containsLog("authn denied 'my.domain.my-name'")
	s.containsLog(msg)
}

func TestAuthnBadInputs(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()

	base := stdAuthnInput(s.token.String())
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
	noToken := func() []byte {
		c := base
		c.Spec.Token = ""
		return serialize(c)
	}
	badToken := func() []byte {
		c := base
		c.Spec.Token = "garbage"
		return serialize(c)
	}
	expiredToken := func() []byte {
		c := base
		tok := stdToken()
		e := time.Now().Add(-1 * time.Minute)
		tok.expiration = &e
		c.Spec.Token = tok.String()
		return serialize(c)
	}

	tests := []struct {
		code  int
		input []byte
		msg   string
	}{
		{400, nil, "empty body for authentication request"},
		{400, badKind(), "unsupported authentication kind, want 'TokenReview', got 'foo'"},
		{400, badVersion(), "unsupported authentication version, want 'authentication.k8s.io/v1beta1', got 'foo'"},
		{400, noToken(), "empty authentication token spec. Must set a token value"},
		{400, append(serialize(base), 'X'), "invalid JSON request"},
		{200, badToken(), "bad field in token 'garbage'"},
		{200, expiredToken(), "token has expired"},
	}
	for _, test := range tests {
		ar := runAuthnTest(s, test.input, nil)
		if ar.w.Code != test.code {
			t.Fatalf("unexpected status code want %d, got %d", test.code, ar.w.Code)
		}
		switch test.code {
		case 200:
			var tr authn.TokenReview
			err := json.Unmarshal(ar.body.Bytes(), &tr)
			if err != nil {
				t.Fatalf("unmarshal error for '%s', %v", ar.body.String(), err)
			}
			if !strings.Contains(tr.Status.Error, test.msg) {
				t.Errorf("error response '%s' did not contain '%s'", tr.Status.Error, test.msg)
			}
		default:
			if !strings.Contains(ar.body.String(), test.msg) {
				t.Errorf("response '%s' did not contain '%s'", ar.body.String(), test.msg)
			}
		}
	}
}

type errum struct {
}

func (e *errum) MapUser(ctx context.Context, p AthenzPrincipal) (authn.UserInfo, error) {
	return authn.UserInfo{}, errors.New("FOOBAR")
}

func TestAuthnUserMappingError(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()
	s.config.Mapper = &errum{}
	s.config.LogFlags = LogTraceAthenz | LogTraceServer
	ap := AthenzPrincipal{
		Domain:  "my.domain",
		Service: "foo",
		Token:   stdToken().String(),
	}
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(testContext, w, ap)
	})
	ar := runAuthnTest(s, serialize(stdAuthnInput(s.token.String())), zmsHandler)
	code := 200
	msg := "FOOBAR"
	if ar.w.Code != code {
		t.Fatalf("unexpected status code want %d, got %d", code, ar.w.Code)
	}
	var tr authn.TokenReview
	err := json.Unmarshal(ar.body.Bytes(), &tr)
	if err != nil {
		t.Fatalf("unmarshal error for '%s', %v", ar.body.String(), err)
	}
	if !strings.Contains(tr.Status.Error, msg) {
		t.Errorf("error response '%s' did not contain '%s'", tr.Status.Error, msg)
	}
	// test debug output
	//t.Log(s.l.b.String())
	for _, line := range []string{
		"POST /authn",
		"request body: {",
		"response status: 200",
		`response: {"Domain":"my.domain"`,
		`authn denied 'my.domain.my-name'`,
		"error=FOOBAR",
	} {
		s.containsLog(line)
	}
}
