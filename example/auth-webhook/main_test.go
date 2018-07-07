package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	authn "k8s.io/api/authentication/v1beta1"
	authz "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"

	"github.com/stretchr/testify/require"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

var (
	origStdout = os.Stdout
	origStderr = os.Stderr
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

// tok writes a valid ntoken to disk and cleans up with the Close method
type tok struct {
	f string
	v []byte
}

func (t *tok) value() []byte {
	return t.v
}

func (t *tok) param() string {
	return fmt.Sprintf("--ntoken-path=%s", t.f)
}

func (t *tok) file() string {
	return t.f
}

func (t *tok) Close() error {
	os.Remove(t.f)
	return nil
}

func newTok(t *testing.T) *tok {
	f, err := ioutil.TempFile("/tmp", "tok")
	if err != nil {
		t.Fatal(err)
	}
	v := []byte(fmt.Sprintf("d=dom;n=name;e=%d;s=sig", time.Now().Add(time.Hour).Unix()))
	f.Write(v)
	f.Close()
	return &tok{f: f.Name(), v: v}
}

func getToken(t *testing.T) string {
	tokenBuilder, err := zmssvctoken.NewTokenBuilder("my.domain", "foo", rsaPrivateKeyPEM, "v1")
	require.Nil(t, err)
	token, err := tokenBuilder.Token().Value()
	require.Nil(t, err)
	return token
}

// streamHijack hijacks stdout and stderr streams and restores them on Close
type streamHijack struct {
	t              *testing.T
	stdout, stderr *os.File
}

// get returns the streams as strings. Should be called exactly once per hijacker.
func (s *streamHijack) get() (stdout, stderr string) {
	b, err := ioutil.ReadFile(s.stdout.Name())
	if err != nil {
		s.t.Fatal(err)
	}
	b2, err := ioutil.ReadFile(s.stderr.Name())
	if err != nil {
		s.t.Fatal(err)
	}
	s.Close()
	return string(b), string(b2)
}

func (s *streamHijack) Close() error {
	if s.stdout != nil {
		s.stdout.Close()
		os.Remove(s.stdout.Name())
		s.stdout = nil
	}
	if s.stderr != nil {
		s.stderr.Close()
		os.Remove(s.stderr.Name())
		s.stderr = nil
	}
	os.Stdout = origStdout
	os.Stderr = origStderr
	return nil
}

func newHijack(t *testing.T) *streamHijack {
	o, err := ioutil.TempFile("/tmp", "athenz-out")
	if err != nil {
		t.Fatal(err)
	}
	e, err := ioutil.TempFile("/tmp", "athenz-err")
	if err != nil {
		o.Close()
		os.Remove(o.Name())
		t.Fatal(err)
	}
	os.Stdout = o
	os.Stderr = e
	return &streamHijack{
		t:      t,
		stdout: o,
		stderr: e,
	}
}

func TestMainVersionValue(t *testing.T) {
	expected := "development version"
	actual := getVersion()
	if expected != actual {
		t.Errorf("bad version, want %q, got %q", expected, actual)
	}
	expected = "foobar"
	Version = expected
	defer func() {
		Version = ""
	}()
	actual = getVersion()
	if expected != actual {
		t.Errorf("bad version, want %q, got %q", expected, actual)
	}
}

func TestMainSplitNames(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"  ", nil},
		{"foo", []string{"foo"}},
		{"  foo ", []string{"foo"}},
		{"foo,bar", []string{"foo", "bar"}},
		{"foo  ,  bar  ", []string{"foo", "bar"}},
	}
	for _, test := range tests {
		actual := splitNames(test.input)
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("split names %q: want %v got %v", test.input, test.expected, actual)
		}
	}
}

func TestMainVersionCommand(t *testing.T) {
	h := newHijack(t)
	defer h.Close()
	_, err := parseFlags("test-driver", []string{"--version"})
	if err != errEarlyExit {
		t.Fatal("show version should respond with earlyexit error")
	}
	sout, _ := h.get()
	if !strings.Contains(sout, getVersion()) {
		t.Errorf("stdout '%s' did not contain '%s'", sout, getVersion())
	}
}

func TestMainParams(t *testing.T) {
	tok := newTok(t)
	defer tok.Close()
	lf, err := ioutil.TempFile("/tmp", "log")
	if err != nil {
		t.Fatal(err)
	}
	lf.Close()
	defer os.Remove(lf.Name())
	var (
		authHeader     = "X-Foo"
		clusterDomain  = "admin"
		groups         = "athenz,sparta"
		helpMsg        = "please tell me what to do"
		key            = "/some/key/path"
		cert           = "/some/cert/path"
		addr           = ":8888"
		adminResources = "resourcequotas,limitranges"
		denyResources  = "apples"
		denyUsers      = "jim,bill"
		zms            = "http://zms.org/v1"
		logFile        = lf.Name()
	)
	arg := func(name, value string) string {
		return fmt.Sprintf("--%s=%s", name, value)
	}
	args := []string{
		tok.param(),
		arg("auth-header", authHeader),
		arg("cluster-domain", clusterDomain),
		arg("groups", groups),
		arg("help-message", helpMsg),
		arg("key", key),
		arg("cert", cert),
		arg("listen", addr),
		arg("policy-admin-resources", adminResources),
		arg("policy-deny-resources", denyResources),
		arg("policy-deny-users", denyUsers),
		arg("zms-url", zms),
		arg("logfile", logFile),
		arg("tls", "false"),
	}
	h := newHijack(t)
	defer h.Close()
	p, err := parseFlags("test-driver", args)
	if err != nil {
		t.Fatal("parse error", err)
	}
	defer p.Close()

	pairs := []struct {
		actual   interface{}
		expected interface{}
	}{
		{p.addr, addr},
		{p.keyFile, key},
		{p.certFile, cert},
		{p.authn.Config.ZMSEndpoint, zms},
		{p.authz.Config.ZMSEndpoint, zms},
		{p.authz.HelpMessage, helpMsg},
		{p.authz.Mapper.(*ResourceMapper).AdminResources, splitNames(adminResources)},
		{p.authz.Mapper.(*ResourceMapper).DenyUsers, splitNames(denyUsers)},
		{p.authz.Mapper.(*ResourceMapper).DenyResources, splitNames(denyResources)},
	}
	for _, pair := range pairs {
		if !reflect.DeepEqual(pair.actual, pair.expected) {
			t.Errorf("param not propagated, want %v, got %v", pair.expected, pair.actual)
		}
	}
}

func TestMainInvalidParams(t *testing.T) {
	tok := newTok(t)
	defer tok.Close()

	tests := []struct {
		input []string
		msg   string
		sout  string
		serr  string
	}{
		{
			[]string{"--foo=bar"},
			"flag provided but not defined: -foo",
			"", "Usage of test-driver:",
		},
		{
			[]string{"--logfile=/non/existent/path.log"},
			"/non/existent/path.log:",
			"", "",
		},
		{
			[]string{"--trace-events=server,athenz, mapping,foobar", "--athenz-timeout=1decade"},
			"invalid athenz client timeout",
			"", "unsupported trace event foobar , ignored",
		},
		{
			[]string{"--token-refresh-interval=1decade"},
			"invalid token refresh interval",
			"", "",
		},
		{
			[]string{"--ntoken-path=/non/existent/path.log"},
			"/non/existent/path.log:",
			"", "",
		},
		{
			[]string{tok.param(), "--shutdown-grace=1decade"},
			"invalid shutdown grace period",
			"", "",
		},
		{
			[]string{tok.param()},
			"must pass both key and cert files when TLS enabled",
			"", "",
		},
	}

	for _, test := range tests {
		h := newHijack(t)
		_, err := parseFlags("test-driver", test.input)
		if err == nil {
			t.Errorf("parse params: %v, expected error got nil", test.input)
		}
		if !strings.Contains(err.Error(), test.msg) {
			t.Errorf("parse params: %v, %q does not contain expected string %q", test.input, err.Error(), test.msg)
		}
		if test.sout != "" || test.serr != "" {
			sout, serr := h.get()
			if !strings.Contains(sout, test.sout) {
				t.Errorf("stdout '%s' did not contain '%s'", sout, test.sout)
			}
			if !strings.Contains(serr, test.serr) {
				t.Errorf("stderr '%s' did not contain '%s'", serr, test.serr)
			}
		}
		h.Close()
	}
}

func TestRunWithInvalidParams(t *testing.T) {
	ch := make(chan struct{})
	f := "/non/existent/path.txt"
	err := run("test-driver", []string{"--ntoken-path=" + f}, ch)
	if err == nil {
		t.Fatal("run did not return error")
	}
	if !strings.Contains(err.Error(), f) {
		t.Errorf("invalid msg '%s', expected to contain '%s'", err.Error(), f)
	}
}

type capture struct {
	path  string
	token string
	body  string
}

func TestRunWithMockZMS(t *testing.T) {
	var records []capture
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "publickey") {
			ybase := zmssvctoken.YBase64{}
			keyString := ybase.EncodeToString(rsaPublicKeyPEM)
			w.Write([]byte(fmt.Sprintf(`{ "key": "%s" }`, keyString)))
			return
		}

		h := r.Header.Get("Athenz-Principal-Auth")
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, capture{
			path:  r.URL.Path,
			token: h,
			body:  string(b),
		})

		w.WriteHeader(401)
	}))
	defer s.Close()
	tok := newTok(t)
	defer tok.Close()

	ch := make(chan struct{})
	done := make(chan error, 1)
	port := 12347
	go func() {
		err := run(
			"test-driver",
			[]string{
				tok.param(),
				"--tls=false",
				fmt.Sprintf("--listen=:%d", port),
				fmt.Sprintf("--zms-url=%s", s.URL),
				fmt.Sprintf("--zts-url=%s", s.URL),
			},
			ch,
		)
		if err != nil {
			t.Log(err)
		}
		done <- err
	}()

	time.Sleep(500 * time.Millisecond)

	tr := authn.TokenReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenReview",
			APIVersion: "authentication.k8s.io/v1beta1",
		},
		Spec: authn.TokenReviewSpec{
			Token: getToken(t),
		},
	}
	sar := authz.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1beta1",
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
	trb, _ := json.Marshal(tr)
	srb, _ := json.Marshal(sar)

	tests := []struct {
		path          string
		method        string
		body          []byte
		statusCode    int
		responseCheck func(respBody []byte)
	}{
		{"/healthz", "GET", nil, 200, nil},
		{"/authn", "GET", nil, 404, nil},
		{"/authz", "GET", nil, 404, nil},
		{"/authn", "POST", nil, 400, nil},
		{"/authn", "POST", trb, 200, nil},
		{"/authz", "POST", nil, 400, nil},
		{"/authz", "POST", srb, 200, nil},
	}

	for _, test := range tests {
		u := fmt.Sprintf("http://127.0.0.1:%d%s", port, test.path)
		var req *http.Request
		var err error
		if len(test.body) == 0 {
			req, err = http.NewRequest(test.method, u, nil)
		} else {
			req, err = http.NewRequest(test.method, u, bytes.NewBuffer(test.body))
		}
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("unexpected error on %s %s, %v", test.method, test.path, err)
		}
		if res.StatusCode != test.statusCode {
			t.Fatalf("bad response on %s %s, want %d got %d", test.method, test.path, test.statusCode, res.StatusCode)
		}
	}
	close(ch)
	err := <-done
	if err != nil {
		t.Fatal("server returned error on explicit close")
	}

	if len(records) != 2 {
		t.Fatalf("zms server not contacted, expected 2 records found %d", len(records))
	}

}
