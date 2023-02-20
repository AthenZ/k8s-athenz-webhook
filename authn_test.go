package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

var rsaPrivateKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
`)

var rsaPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----
`)

func getToken(t *testing.T) string {
	tokenBuilder, err := zmssvctoken.NewTokenBuilder("my.domain", "foo", rsaPrivateKeyPEM, "v1")
	require.Nil(t, err)
	token, err := tokenBuilder.Token().Value()
	require.Nil(t, err)
	return token
}

type mpfn func(ctx context.Context, domain, service string) (authn.UserInfo, error)

func (m mpfn) MapUser(ctx context.Context, domain, service string) (authn.UserInfo, error) {
	return m(ctx, domain, service)
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
			ZMSEndpoint: m.URL,
			Timeout:     200 * time.Millisecond,
			LogProvider: p,
		},
		Mapper: mpfn(func(ctx context.Context, domain, service string) (authn.UserInfo, error) {
			return authn.UserInfo{
				Username: domain + "." + service,
				UID:      "100",
				Groups:   []string{"foo"},
			}, nil
		}),
	}
	c.Validator = zmssvctoken.NewTokenValidator(zmssvctoken.ValidationConfig{
		ZTSBaseUrl:            m.URL,
		PublicKeyFetchTimeout: 30 * time.Second,
		CacheTTL:              2 * time.Hour,
	})
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
	token := getToken(t)
	input := stdAuthnInput(token)

	ap := AthenzPrincipal{
		Domain:  "my.domain",
		Service: "foo",
		Token:   token,
	}
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "publickey") {
			ybase := zmssvctoken.YBase64{}
			keyString := ybase.EncodeToString(rsaPublicKeyPEM)
			w.Write([]byte(fmt.Sprintf(`{ "key": "%s" }`, keyString)))
			return
		}

		writeJSON(testContext, w, ap)
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
	expected := authn.UserInfo{
		Username: "my.domain.foo",
		UID:      "100",
		Groups:   []string{"foo"},
	}
	if !reflect.DeepEqual(expected, tr.Status.User) {
		t.Errorf("bad output, want %v got %v", expected, tr.Status.User)
	}
	s.containsLog("authn granted 'my.domain.foo'")
	s.containsLog("-> user=my.domain.foo, uid=100, groups=[foo]")
}

func TestAuthnZMSReject(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()
	input := stdAuthnInput(getToken(t))
	zmsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := struct{ Message string }{"Unauthorized"}
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
	msg := "/principal returned 401 (Unauthorized)"
	if !strings.Contains(tr.Status.Error, msg) {
		t.Errorf("status log '%s' did not contain '%s'", tr.Status.Error, msg)
	}
	s.containsLog("authn denied 'my.domain.foo'")
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
		{400, badVersion(), "unsupported authentication version, want 'authentication.k8s.io/v1', got 'foo'"},
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

func (e *errum) MapUser(ctx context.Context, domain, service string) (authn.UserInfo, error) {
	return authn.UserInfo{}, errors.New("FOOBAR")
}

func TestAuthnUserMappingError(t *testing.T) {
	s := newAuthnScaffold(t)
	defer s.Close()
	s.config.Mapper = &errum{}
	s.config.LogFlags = LogTraceAthenz | LogTraceServer
	ztsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ybase := zmssvctoken.YBase64{}
		keyString := ybase.EncodeToString(rsaPublicKeyPEM)
		w.Write([]byte(fmt.Sprintf(`{ "key": "%s" }`, keyString)))
		return
	})
	ar := runAuthnTest(s, serialize(stdAuthnInput(getToken(t))), ztsHandler)
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
		`authn denied 'my.domain.foo'`,
		"error=FOOBAR",
	} {
		s.containsLog(line)
	}
}
