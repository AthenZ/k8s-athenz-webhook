// Command auth-webhook provides a reference implementation for the K8s Athenz web hook
// for authentication and authorization. This is an opinionated implementation that performs
// user and resource mapping from k8s to Athenz in a specific way. The mapping code is
// extensively documented for rationale. You can use the program directly if it meets your
// needs. If not, you can still use the underlying API and supply custom mapping code
// and the main entry point.
//
// It exposes three endpoints, `/authn` for the authentication handler, `/authz` for the
// authorization handler, and `/healthz` that always returns a 200 OK response.
//
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	api "github.com/yahoo/k8s-athenz-webhook"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

const (
	defaultPort       = 443
	defaultNtokenPath = `/tokens/ntoken`
	defaultZMSURL     = `https://localhost/zms/v1`
	defaultZTSURL     = `https://localhost/zts/v1`
)

var (
	defaultDenyUsers      = []string{"system:anonymous"}
	defaultDenyResources  = []string{"podsecuritypolicies"}
	defaultAdminResources = []string{"resourcequotas", "limitranges", "namespaces"}
)

// Version gets set by the build script via LDFLAGS
var Version string

func getVersion() string {
	if Version == "" {
		return "development version"
	}
	return Version
}

type params struct {
	addr     string
	tls      bool
	certFile string
	keyFile  string
	authn    api.AuthenticationConfig
	authz    api.AuthorizationConfig
	closers  []io.Closer
	shutdown time.Duration
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func splitNames(s string) []string {
	if strings.Trim(s, " \t") == "" {
		return nil
	}
	list := strings.Split(s, ",")
	ret := make([]string, 0, len(list))
	for _, e := range list {
		ret = append(ret, strings.Trim(e, " \t"))
	}
	return ret
}

var errEarlyExit = errors.New("early exit")

func parseFlags(program string, args []string) (*params, error) {
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	join := func(list []string) string { return strings.Join(list, ",") }
	var p params
	var c api.Config
	var ntokenPath, logFile, adminDomain, k8sGroups, traceEvents, help string
	var validateToken, showVersion bool
	var tokenInterval, timeout, shutdownGrace string
	var policyDenyUsers, policyDenyResources, policyAdminResources string

	f.StringVar(&p.addr, "listen", fmt.Sprintf("127.0.0.1:%d", defaultPort), "<ip>:<port> to listen on")
	f.BoolVar(&p.tls, "tls", true, "TLS enable/disable")
	f.StringVar(&p.certFile, "cert", "", "Path to TLS cert")
	f.StringVar(&p.keyFile, "key", "", "Path to TLS key file")
	f.StringVar(&logFile, "logfile", "", "File to write logs to. Defaults to stderr")
	f.StringVar(&ntokenPath, "ntoken-path", defaultNtokenPath, "Path to ntoken")
	f.StringVar(&c.ZMSEndpoint, "zms-url", defaultZMSURL, "URL to the ZMS endpoint")
	f.StringVar(&c.ZTSEndpoint, "zts-url", defaultZTSURL, "URL to the ZTS endpoint")
	f.StringVar(&c.AuthHeader, "auth-header", "Athenz-Principal-Auth", "Athenz auth header name")
	f.BoolVar(&validateToken, "validate-token", true, "Validate the identity ntoken on load")
	f.StringVar(&k8sGroups, "groups", "", "comma-separated list of k8s groups to add to user info")
	f.BoolVar(&showVersion, "version", false, "Show version information")
	f.StringVar(&traceEvents, "trace-events", "", "comma-separated events to trace. Values recognized are server|athenz|mapping")
	f.StringVar(&tokenInterval, "token-refresh-interval", "1m", "interval to refresh ntoken from file")
	f.StringVar(&timeout, "athenz-timeout", "10s", "timeout for Athenz requests")
	f.StringVar(&help, "help-message", "", "help message to be returned on authorization errors")
	f.StringVar(&shutdownGrace, "shutdown-grace", "10s", "grace period for connections to drain at shutdown")

	f.StringVar(&adminDomain, "cluster-domain", "kubernetes", "Athenz domain for administration of this cluster")
	f.StringVar(&policyDenyUsers, "policy-deny-users", join(defaultDenyUsers), "comma-separated users to deny")
	f.StringVar(&policyDenyResources, "policy-deny-resources", join(defaultDenyResources), "comma-separated resources to deny")
	f.StringVar(&policyAdminResources, "policy-admin-resources", join(defaultAdminResources), "comma-separated resources to treat as admin")

	err := f.Parse(args)
	if err != nil {
		return nil, err
	}

	if showVersion {
		fmt.Println(getVersion())
		return nil, errEarlyExit
	}

	// init logging
	traces := splitNames(traceEvents)
	for _, t := range traces {
		switch strings.ToLower(t) {
		case "server":
			c.LogFlags |= api.LogTraceServer
		case "athenz":
			c.LogFlags |= api.LogTraceAthenz
		case "mapping":
			c.LogFlags |= api.LogVerboseMapping
		default:
			fmt.Fprintln(os.Stderr, "unsupported trace event", t, ", ignored")
		}
	}

	w := os.Stderr
	if logFile != "" {
		w, err = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		p.closers = append(p.closers, w)
	}

	c.LogProvider = NewLogProvider(w)
	c.Timeout, err = time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid athenz client timeout %q, %v", timeout, err)
	}

	// init token provider
	fti, err := time.ParseDuration(tokenInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid token refresh interval %q, %v", tokenInterval, err)
	}

	ft, err := NewFileToken(ntokenPath, validateToken, fti)
	if err != nil {
		return nil, err
	}
	p.closers = append(p.closers, ft)

	p.shutdown, err = time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace period %q, %v", shutdownGrace, err)
	}

	if p.tls {
		if p.certFile == "" || p.keyFile == "" {
			return nil, errors.New("must pass both key and cert files when TLS enabled")
		}
	}

	// init mappers and configs
	groups := splitNames(k8sGroups)
	p.authn = api.AuthenticationConfig{
		Config: c,
		Mapper: &UserMapper{
			Groups: groups,
		},
	}
	p.authn.Config.Validator = zmssvctoken.NewTokenValidator(zmssvctoken.ValidationConfig{
		ZTSBaseUrl:            c.ZTSEndpoint,
		PublicKeyFetchTimeout: 30 * time.Second,
		CacheTTL:              2 * time.Hour,
	})
	p.authz = api.AuthorizationConfig{
		Config: c,
		Token:  ft.TokenValue,
		Mapper: &ResourceMapper{
			AdminDomain:    adminDomain,
			DenyUsers:      splitNames(policyDenyUsers),
			DenyResources:  splitNames(policyDenyResources),
			AdminResources: splitNames(policyAdminResources),
		},
		HelpMessage: help,
	}
	return &p, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	p, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer p.Close()

	postOnly := func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, "only POST is supported for this endpoint")
				return
			}
			delegate.ServeHTTP(w, r)
		})
	}

	authn := api.NewAuthenticator(p.authn)
	authz := api.NewAuthorizer(p.authz)
	healthz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux := http.NewServeMux()
	mux.Handle("/authn", postOnly(authn))
	mux.Handle("/authz", postOnly(authz))
	mux.Handle("/healthz", healthz)
	s := &http.Server{
		Addr:    p.addr,
		Handler: mux,
	}

	done := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			done <- err
		}()
		log.Printf("%s (%s)\n", program, getVersion())
		if p.tls {
			log.Printf("start TLS server on %s\n", p.addr)
			err = s.ListenAndServeTLS(p.certFile, p.keyFile)
		} else {
			log.Printf("start server on %s\n", p.addr)
			err = s.ListenAndServe()
		}
	}()

	stopped := false
	for {
		select {
		case err := <-done:
			if stopped {
				return nil
			}
			return err
		case <-stopChan:
			stopChan = nil // prevent additional channel firing
			stopped = true
			ctx, fn := context.WithTimeout(context.Background(), p.shutdown)
			defer fn()
			s.Shutdown(ctx)
		}
	}
}

func main() {
	stopChan := make(chan struct{})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-ch
		log.Println("shutting down...")
		close(stopChan)
	}()
	err := run(filepath.Base(os.Args[0]), os.Args[1:], stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln("[FATAL]", err)
	}
}
