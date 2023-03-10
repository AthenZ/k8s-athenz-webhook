// Package webhook provides the handlers and customization points for implementing a K8s webhook
// for authentication and authorization using Athenz.
package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

// DefaultClientTimeout is used when no timeout is supplied in the config.
var DefaultClientTimeout = 10 * time.Second

// LogFlags is a bitwise mask of additional logging that is required. The zero value produces standard logs
// that produce one line of the outcome for both authn and authz.
type LogFlags int

// Log flag constants
const (
	_                 LogFlags = 1 << iota // standard logging only
	LogVerboseMapping                      // user mapping code can use this for verbosity
	LogTraceServer                         // log details of server requests, insecure
	LogTraceAthenz                         // log details of Athenz HTTP calls, insecure
)

// Logger is the minimal logging interface required by the API.
type Logger interface {
	// Println has the same semantics as the log package.
	Println(args ...interface{})
	// Printf has the same semantics as the log package.
	Printf(format string, args ...interface{})
}

// LogProvider produces a Logger given a request identifier.
type LogProvider func(requestID string) Logger

// IsLogEnabled returns true if the supplied flag is set in the configuration log flags bitmask.
func IsLogEnabled(ctx context.Context, flag LogFlags) bool {
	return isLogEnabled(ctx, flag)
}

// GetLogger returns the logger for the supplied context.
func GetLogger(ctx context.Context) Logger {
	return getLogger(ctx)
}

// IdentityToken provides an ntoken for Athenz access for the authorization handler itself.
type IdentityToken func() (string, error)

// IdentityAthenzX509 provides x509 certs for Athenz access
type IdentityAthenzX509 func() (*tls.Config, error)

// AthenzPrincipal represents a valid Athenz principal.
type AthenzPrincipal struct {
	Domain  string // Athenz domain
	Service string // local name
	Token   string // the token
}

// UserMapper allows for mapping from Athenz principals to k8s objects.
type UserMapper interface {
	// MapUser maps an Athenz principal to a user info object.
	// Returning an error will cause an authentication failure.
	MapUser(ctx context.Context, domain, service string) (authn.UserInfo, error)
}

// AthenzAccessCheck encapsulates the parameters for an authz check against Athenz.
type AthenzAccessCheck struct {
	Action   string // the action to authorize
	Resource string // fully qualified Athenz resource name including domain prefix (e.g. "my.domain:the-resource")
}

func (a AthenzAccessCheck) String() string {
	return fmt.Sprintf("%s on %s", a.Action, a.Resource)
}

// ResourceMapper allows for mapping from an authorization request to Athenz entities.
type ResourceMapper interface {
	// MapResource maps a subject review spec into a principal and a list of Athenz
	// authz checks at least one of which must succeed. An empty list implies no
	// authorization. An error must be returned  if the mapper is not able or
	// unwilling to map the supplied spec into Athenz checks.
	// Returning multiple items allows the implementor to add a secondary
	// authz request for superuser access, for example.
	MapResource(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error)
}

// Config is the common configuration for authn and authz
type Config struct {
	ZMSEndpoint string                     // ZMS endpoint including version specific (e.g. /v1) path
	ZTSEndpoint string                     // ZTS endpoint including version specific (e.g. /v1) path
	AuthHeader  string                     // header name for ntoken in Athenz requests
	Timeout     time.Duration              // timeout for all Athenz requests
	LogProvider LogProvider                // the log provider
	LogFlags    LogFlags                   // logging flags
	Validator   zmssvctoken.TokenValidator // token validator
	Cache       *Cache                     // AthenzDomain Cache
	UseCache    bool                       // UseCache flag
	DryRun      bool                       // DryRun mode flag
}

func (c *Config) initDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultClientTimeout
	}
	if c.LogProvider == nil {
		c.LogProvider = func(prefix string) Logger {
			return log.New(os.Stderr, prefix, log.LstdFlags)
		}
	}
}

// AuthenticationConfig is the authentication configuration
type AuthenticationConfig struct {
	Config            // base config
	Mapper UserMapper // user mapper
}

// AuthorizationConfig is the authorization configuration
type AuthorizationConfig struct {
	Config                                       // the base config
	HelpMessage               string             // additional message for the user on internal authz errors
	Token                     IdentityToken      // the token provider for calls to Athenz
	AthenzX509                IdentityAthenzX509 // the x509 provider for calls to Athenz
	AthenzClientAuthnx509Mode bool               // enable/disable x509 mode for Identity athenz x509
	Mapper                    ResourceMapper     // the resource mapper
}

// NewAuthenticator returns a handler that can service an authentication request.
func NewAuthenticator(c AuthenticationConfig) http.Handler {
	if c.Mapper == nil {
		panic("no user mapper in authenticator config")
	}
	c.initDefaults()
	return wrapHandler(newAuthn(c), c.Config)
}

// NewAuthorizer returns a handler that can service an authorization request.
func NewAuthorizer(c AuthorizationConfig) http.Handler {
	if c.Mapper == nil {
		panic("no resource mapper in authorizer config")
	}
	c.initDefaults()
	return wrapHandler(newAuthz(c), c.Config)
}

// VerifyToken returns an error if the supplied ntoken was not
// well-formed. When checkExpiry is true, an expiry check on the
// token is also performed.
func VerifyToken(token string, checkExpiry bool) error {
	nt, err := newNToken(token)
	if err == nil && checkExpiry {
		err = nt.checkExpiry()
	}
	return err
}
