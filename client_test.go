package webhook

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthTransport(t *testing.T) {
	resp := []byte("this is a test")
	token := "this is a token"
	xp := newAuthTransport("X-Foo", token)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Y-Foo", r.Header.Get("X-Foo"))
		w.WriteHeader(400)
		w.Write(resp)
	}))
	defer server.Close()
	client := &http.Client{
		Transport: xp,
	}
	res, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("server error", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 400 {
		t.Error("bad status code", res.StatusCode)
	}
	b, _ := ioutil.ReadAll(res.Body)
	if !bytes.Equal(resp, b) {
		t.Errorf("bad resp want '%s' got '%s", resp, b)
	}
	h := res.Header.Get("Y-Foo")
	if h != token {
		t.Errorf("token not propagated, want '%s', got '%s'", token, h)
	}
}

func TestDebugTransport(t *testing.T) {
	reqBody := []byte("this is the input")
	respBody := []byte("this is the output")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Foo", r.Header.Get("X-Foo"))
		w.Header().Set("Y-Foo", "Response")
		w.Header().Add("Y-Multi", "one")
		w.Header().Add("Y-Multi", "two")
		w.WriteHeader(400)
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b[:4])
		w.Write(respBody)
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Foo", "Request")
	req.Header.Add("X-Multi", "one")
	req.Header.Add("X-Multi", "two")
	logger := newlp()
	xp := &debugTransport{
		RoundTripper: http.DefaultTransport,
		log:          logger,
	}
	client := &http.Client{
		Transport: xp,
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 400 {
		t.Error("bad status code", res.StatusCode)
	}
	h := res.Header.Get("X-Foo")
	if h != "Request" {
		t.Errorf("X-Foo header not propagated to server")
	}
	h = res.Header.Get("Y-Foo")
	if h != "Response" {
		t.Errorf("Y-Foo header not returned from server")
	}
	b, _ := ioutil.ReadAll(res.Body)
	rb := append(reqBody[:4], respBody...)
	if !bytes.Equal(rb, b) {
		t.Errorf("bad resp want '%s' got '%s", rb, b)
	}

	log := logger.b.String()
	contains := func(s string) {
		if !strings.Contains(log, s) {
			t.Errorf("log '%s' did not contain '%s'", log, s)
		}
	}

	contains("POST " + server.URL)
	contains("X-Foo: Request")
	contains("X-Multi: [one two]")
	contains("this is the input")
	contains("Y-Foo: Response")
	contains("Y-Multi: [one two]")
	contains("response: thisthis is the output")

	// request error test
	logger.b.Reset()
	_, err = client.Get("http://does.not.exist")
	if err == nil {
		t.Fatal("non-existent domain http call succeeded")
	}
	log = logger.b.String()
	contains("request error")
}

func TestExtractMessage(t *testing.T) {
	m := "this is a test"
	s := `{ "message": "` + m + `" }`
	out := extractMessage([]byte(s))
	if out != m {
		t.Fatalf("want '%s', got '%s'", m, out)
	}
	out = extractMessage([]byte("junk"))
	e := "no message found"
	if out != e {
		t.Errorf("want '%s', got '%s", e, out)
	}
}

func marshaler(data interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(context.Background(), w, data)
	})
}

func requestTester(handler http.Handler, data interface{}, validator func([]byte) error, asserter func(error)) {
	server := httptest.NewServer(handler)
	defer server.Close()
	if handler == nil {
		server.Close() // make endpoint not respond
	}
	client := newClient(server.URL, server.URL, 200*time.Millisecond, http.DefaultTransport)
	err := client.request(server.URL, data, validator)
	asserter(err)
}

func TestClientRequestHappyPath(t *testing.T) {
	p := AthenzPrincipal{Domain: "d", Service: "s", Token: "t"}
	var ret AthenzPrincipal
	h := marshaler(p)
	requestTester(h, &ret, nil, func(err error) {
		if err != nil {
			t.Fatal("expected success got", err)
		}
		if p != ret {
			t.Fatal("input output mismatch, want", p, ",got", ret)
		}
	})
}

func TestClientReqConnError(t *testing.T) {
	requestTester(nil, nil, nil, func(err error) {
		if err == nil {
			t.Fatal("expected error got success")
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatal("invalid error", err)
		}
	})
}

func TestClientBadStatusCode(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	requestTester(h, nil, nil, func(err error) {
		if err == nil {
			t.Fatal("expected error got success")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Fatal("invalid error", err)
		}
		e, ok := err.(*statusCodeError)
		if !ok {
			t.Fatal("status code not propagated")
		}
		if e.code != 404 {
			t.Error("invalid status code, want", 404, ", got", e.code)
		}
	})
}

func TestClientBadJSON(t *testing.T) {
	var p AthenzPrincipal
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{ x: y}"))
	})
	requestTester(h, &p, nil, func(err error) {
		if err == nil {
			t.Fatal("expected error got success")
		}
		if !strings.Contains(err.Error(), "JSON") {
			t.Fatal("invalid error", err)
		}
	})
}

func TestClientBadValidator(t *testing.T) {
	var p AthenzPrincipal
	h := marshaler(p)
	v := func(b []byte) error {
		return errors.New("FOOBAR")
	}
	requestTester(h, &p, v, func(err error) {
		if err == nil {
			t.Fatal("expected error got success")
		}
		if err.Error() != "FOOBAR" {
			t.Fatal("invalid error", err)
		}
	})
}

func TestClientTimeout(t *testing.T) {
	var p AthenzPrincipal
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("{}"))
	})
	requestTester(h, &p, nil, func(err error) {
		if err == nil {
			t.Fatal("expected error got success")
		}
		if !strings.Contains(err.Error(), "Client.Timeout exceeded") {
			t.Fatal("invalid error", err)
		}
	})
}

func TestClientAuthorize(t *testing.T) {
	p := struct{ Granted bool }{true}
	h := marshaler(p)
	server := httptest.NewServer(h)
	defer server.Close()
	client := newClient(server.URL, server.URL, 200*time.Millisecond, http.DefaultTransport)
	granted, err := client.authorize(context.Background(), "me", AthenzAccessCheck{Resource: "d:service", Action: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Error("bad grant flag")
	}
}

func TestClientAuthorizeFail(t *testing.T) {
	server := httptest.NewServer(nil)
	server.Close()
	client := newClient(server.URL, server.URL, 200*time.Millisecond, http.DefaultTransport)
	granted, err := client.authorize(context.Background(), "me", AthenzAccessCheck{Resource: "d:service", Action: "read"})
	if err == nil {
		t.Fatal("expected error, got success")
	}
	if granted {
		t.Error("bad grant flag")
	}
}
