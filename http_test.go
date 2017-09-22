package webhook

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHTTPRequestIDSimple(t *testing.T) {
	req := newReqID()
	if req == "unknown" {
		t.Error("unknown request received")
	}
	r2 := newReqID()
	if req == r2 {
		t.Error("same request ID returned in successive calls", r2, req)
	}
}

func TestHTTPRequestIDScale(t *testing.T) {
	workers := 5
	idsPerRoutine := 100
	total := workers * idsPerRoutine
	var l sync.Mutex
	stash := make(map[string]bool, total)
	wait := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-wait
			for i := 0; i < idsPerRoutine; i++ {
				r := newReqID()
				l.Lock()
				stash[r] = true
				l.Unlock()
			}
		}()
	}
	close(wait)
	wg.Wait()
	if len(stash) != total {
		t.Errorf("id collision for %d ids, got %d uniques", total, len(stash))
	}
}

func TestHTTPContextLogger(t *testing.T) {
	l := newlp()
	config := Config{
		LogFlags: LogTraceAthenz | LogVerboseMapping,
		LogProvider: func(id string) Logger {
			l.id = id
			return l
		},
	}
	var r http.Request
	r2 := requestWithContext(&r, config)
	if r2 == &r {
		t.Fatal("request not modified for context")
	}
	if l.id == "" {
		t.Fatal("logger was not requested")
	}

	logger := GetLogger(r2.Context())
	logger.Printf("%s %s", "hello", "world")
	logger.Println("goodbye", "world")

	e := IsLogEnabled(r2.Context(), LogTraceAthenz)
	if !e {
		t.Error("bad trace athenz flag, want true")
	}

	e = IsLogEnabled(r2.Context(), LogTraceServer)
	if e {
		t.Error("bad trace server flag, want false")
	}

	lines := strings.Split(strings.TrimRight(l.b.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatal("invalid lines in buffer, want 2, got", len(lines))
	}
	expected := []string{"hello world", "goodbye world"}
	for i, e := range expected {
		if e != lines[i] {
			t.Errorf("bad msg, want %q, got %q", e, lines[i])
		}
	}
}

func TestHTTPContextNoLogger(t *testing.T) {
	c := context.Background()
	logger := GetLogger(c)
	if logger == nil {
		t.Error("nil logger returned for invalid context")
	}
	e := IsLogEnabled(c, LogTraceServer)
	if e {
		t.Error("bad trace server flag, should always be false for invalid context")
	}
}

func TestHTTPWrapHandler(t *testing.T) {
	l := newlp()
	handler := wrapHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		}),
		Config{
			LogFlags: LogTraceServer,
			LogProvider: func(id string) Logger {
				l.id = id
				return l
			},
		},
	)
	body := bytes.NewBufferString("hello world")
	r := httptest.NewRequest("POST", "/foo", body)
	r.Header.Set("Input-Foo", "Bar")
	r.Header.Add("Input-Bar", "Beer")
	r.Header.Add("Input-Bar", "Wine")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != 404 {
		t.Fatal("delegate handler was not called")
	}
	capture := l.b.String()
	for _, s := range []string{"server request from", "POST /foo", "Input-Foo : Bar", "Input-Bar : [Beer Wine]", "end headers"} {
		if !strings.Contains(capture, s) {
			t.Errorf("log %q does not contain %q", capture, s)
		}
	}
}

func TestHTTPWrapHandlerNoTrace(t *testing.T) {
	l := newlp()
	handler := wrapHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}),
		Config{
			LogFlags: LogVerboseMapping,
			LogProvider: func(id string) Logger {
				l.id = id
				return l
			},
		},
	)
	r := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	capture := l.b.String()
	if capture != "" {
		t.Fatal("logs found when tracing not enabled", capture)
	}
}

func TestHTTPWriteJSON(t *testing.T) {
	l := newlp()
	config := Config{
		LogProvider: func(id string) Logger {
			l.id = id
			return l
		},
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	r2 := requestWithContext(r, config)
	data := struct {
		Foo string
		Bar string
	}{"foo", "bar"}
	var body bytes.Buffer
	w := httptest.NewRecorder()
	w.Body = &body
	writeJSON(r2.Context(), w, data)
	if len(w.HeaderMap["Content-Type"]) != 1 {
		t.Fatal("no content-type set in header")
	}
	if w.HeaderMap["Content-Type"][0] != "application/json" {
		t.Error("bad content type header", w.HeaderMap["Content-Type"][0])
	}
	expected := `{"Foo":"foo","Bar":"bar"}`
	if expected != body.String() {
		t.Errorf("bad body, want '%s' got '%s'", expected, body.String())
	}
	if l.b.String() != "" {
		t.Errorf("nothing should be printed to logger, found '%s", l.b.String())
	}
}

type node struct {
}

func (n *node) MarshalJSON() ([]byte, error) {
	return nil, errors.New("FOOBAR")
}

func TestHTTPWriteBadJSON(t *testing.T) {
	l := newlp()
	config := Config{
		LogProvider: func(id string) Logger {
			l.id = id
			return l
		},
	}
	r := httptest.NewRequest("GET", "/foo", nil)
	r2 := requestWithContext(r, config)

	n := &node{}
	var body bytes.Buffer
	w := httptest.NewRecorder()
	w.Body = &body
	writeJSON(r2.Context(), w, n)

	es := l.b.String()
	for _, e := range []string{"internal serialization error", "FOOBAR"} {
		if !strings.Contains(es, e) {
			t.Errorf("Error string '%s' did not contain '%s'", es, e)
		}
	}
	if w.Code != 500 {
		t.Errorf("500 error was not set")
	}
	es = "internal serialization error\n"
	if body.String() != es {
		t.Errorf("bad external message want '%q' got '%q", es, body.String())
	}
}
