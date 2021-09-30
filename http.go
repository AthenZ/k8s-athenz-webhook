package webhook

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// this file contains http and context helpers

var logKey = struct{}{}

// writeJSON writes the supplied data as JSON to the response writer.
func writeJSON(ctx context.Context, w http.ResponseWriter, data interface{}) {
	b, err := json.Marshal(data)
	if err != nil {
		getLogger(ctx).Printf("internal serialization error, %v", err)
		http.Error(w, "internal serialization error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func newReqID() string {
	id := "unknown"
	b := make([]byte, 5)
	_, err := rand.Reader.Read(b)
	if err == nil {
		id = strings.ToLower(base32.StdEncoding.EncodeToString(b))
	}
	return id
}

type logDet struct {
	log   Logger
	flags LogFlags
}

func requestWithContext(r *http.Request, config Config) *http.Request {
	l := config.LogProvider(newReqID())
	c := context.WithValue(r.Context(), logKey, &logDet{
		log:   l,
		flags: config.LogFlags,
	})
	return r.WithContext(c)
}

func isLogEnabled(ctx context.Context, l LogFlags) bool {
	v, ok := ctx.Value(logKey).(*logDet)
	if ok {
		return v.flags&l != 0
	}
	return false
}

func getLogger(ctx context.Context) Logger {
	v, ok := ctx.Value(logKey).(*logDet)
	if ok {
		return v.log
	}
	return log.New(os.Stderr, "", log.LstdFlags)
}

func wrapHandler(delegate http.Handler, config Config) http.Handler {
	dumpRequest := func(l Logger, r *http.Request) {
		l.Println("server request from", r.RemoteAddr, r.Method, r.URL)
		for k, v := range r.Header {
			if len(v) == 1 {
				l.Println("\t", k, ":", v[0])
			} else {
				l.Println("\t", k, ":", v)
			}
		}
		l.Println("end headers")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := requestWithContext(r, config)
		ctx := req.Context()
		if isLogEnabled(ctx, LogTraceServer) {
			dumpRequest(getLogger(ctx), req)
		}
		delegate.ServeHTTP(w, req)
	})
}
