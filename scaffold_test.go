package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

var testContext = context.Background()

func serialize(data interface{}) []byte {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}

// lp is a Logger implementation that provides access to
// what was logged
type lp struct {
	*log.Logger
	b  *bytes.Buffer
	id string
}

func newlp() *lp {
	b := bytes.NewBuffer(nil)
	l := log.New(b, "", 0)
	return &lp{
		Logger: l,
		b:      b,
	}
}

func logProvider() (*lp, LogProvider) {
	l := newlp()
	return l, func(id string) Logger {
		l.id = id
		return l
	}
}

type fakeToken struct {
	domain       string
	name         string
	expiration   *time.Time
	signature    string
	expireString string
}

func (f *fakeToken) String() string {
	s := []string{}
	if f.domain != "" {
		s = append(s, fmt.Sprintf("%s=%s", keyDomain, f.domain))
	}
	if f.name != "" {
		s = append(s, fmt.Sprintf("%s=%s", keyName, f.name))
	}
	if f.expireString != "" {
		s = append(s, fmt.Sprintf("%s=%s", keyExpiration, f.expireString))
	} else if f.expiration != nil {
		s = append(s, fmt.Sprintf("%s=%d", keyExpiration, f.expiration.Unix()))
	}
	if f.signature != "" {
		s = append(s, fmt.Sprintf("%s=%s", keySignature, f.signature))
	}
	return strings.Join(s, ";")
}

func stdToken() *fakeToken {
	e := time.Now().Add(time.Hour)
	return &fakeToken{
		domain:     "my.domain",
		name:       "my-name",
		expiration: &e,
		signature:  "my-signature",
	}
}

// mockZMS is a mock ZMS implementation. You create one of these and you can then
// swap handlers for testing multiple scenarios in a test. Not concurrency safe.
type mockZMS struct {
	*httptest.Server
	h http.Handler
}

func newMockZMS() *mockZMS {
	m := &mockZMS{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.h == nil {
			msg := struct{ Message string }{"no handler setup"}
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(context.Background(), w, msg)
			return
		}
		m.h.ServeHTTP(w, r)
	}))
	m.Server = s
	return m
}
