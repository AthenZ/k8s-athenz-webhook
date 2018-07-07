package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	api "github.com/yahoo/k8s-athenz-webhook"
	authn "k8s.io/api/authentication/v1beta1"
	authz "k8s.io/api/authorization/v1beta1"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

// this file contains implementations for the user mapper,
// resource mapper and token provider.

const (
	serviceAccountPrefix = "system:serviceaccount:"
)

// UserMapper implements a user mapper that returns a User object
// with the username and UID fields set to the Athenz principal, optionally
// belonging to one or more fixed groups configured at construction.
type UserMapper struct {
	Groups []string // groups to which every Athenz-authenticated principal is added
}

// MapUser implements the UserMapper interface as documented for the type.
func (d *UserMapper) MapUser(ctx context.Context, token *zmssvctoken.NToken) (authn.UserInfo, error) {
	principal := fmt.Sprintf("%s.%s", token.Domain, token.Name)
	return authn.UserInfo{
		Username: principal,
		UID:      principal,
		Groups:   d.Groups,
	}, nil
}

// isReadAccess returns if read access is being requested
func isReadAccess(verb string) bool {
	return verb == "get" || verb == "list" || verb == "watch"
}

// isSystemNamespace returns true if the namespace is a system namespace.
func isSystemNamespace(ns string) bool {
	return strings.HasPrefix(ns, "kube-")
}

// ResourceMapper provides a resource mapper that does the following:
//
// - extracts the input from one of resource attributes and non-resource attributes. Sub-resources are taken
// into account.
//
// - converts the resource namespace to an Athenz domain as documented in the DomainFromNamespace method.
//
// - converts the input principal to an Athenz principal as documented in the PrincipalFromUser method.
//
// - returns an error for unsupported principals and resources
//
// - conditionally maps certain resources as "admin" resources for write operations even if they are namespaced.
//
// - returns one auth check for all write operations based on the above mapping.
//
// - for read access, adds a secondary auth checks for cluster admin access so that these roles
// have full read access on all resources in all namespaces.
//
type ResourceMapper struct {
	AdminDomain    string   // the admin domain to use for system resources
	AdminResources []string // namespaced resourced that should be treated as system resources for write
	DenyUsers      []string // users that should be automatically denied
	DenyResources  []string // resources that should be automatically denied
}

// RestoreDomainName restores the original Athens domain name from the namespace name.
// This assumes that Athenz domains are turned into DNS-safe k8s namespaces
// by converting dots to dashes and literal dashes to two consecutive dashes.
// Thus, an Athenz domain called "foo.bar-baz" is turned into the k8s "foo-bar--baz"
// namespace. This function reverses the mapping to get the original name back.
func RestoreDomainName(ns string) string {
	domain := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(domain, "..", "-", -1)
}

// DomainFromNamespace returns the Athenz domain that a given namespace maps to:
//
// - if the namespace is empty, the admin domain is returned.
//
// - any namespace that starts with 'kube-' is converted to an Athenz sub-domain of the same name
// under the admin domain.
//
// - all other namespaces are returned as is, modified for k8s to Athenz differences.
//
func (d *ResourceMapper) DomainFromNamespace(ns string) string {
	if ns == "" {
		return d.AdminDomain
	}
	if isSystemNamespace(ns) {
		return fmt.Sprintf("%s.%s", d.AdminDomain, ns)
	}
	return RestoreDomainName(ns)
}

// PrincipalFromUser takes a username and returns an Athenz identity.
//
// - service accounts are turned into Athenz services in the mapped domain of the service account namespace.
//
// - Non-service accounts are returned unmodified
//
func (d *ResourceMapper) PrincipalFromUser(user string) string {
	if strings.HasPrefix(user, serviceAccountPrefix) {
		u := strings.TrimPrefix(user, serviceAccountPrefix)
		parts := strings.Split(u, ":")
		if len(parts) >= 2 {
			domain := d.DomainFromNamespace(parts[0])
			return fmt.Sprintf("%s.%s", domain, parts[1])
		}
	}
	return user
}

func inList(s string, list []string) bool {
	for _, e := range list {
		if s == e {
			return true
		}
	}
	return false
}

// MapResource implements the ResourceMapper interface as documented for the type.
func (d *ResourceMapper) MapResource(ctx context.Context, spec authz.SubjectAccessReviewSpec) (string, []api.AthenzAccessCheck, error) {
	var namespace, verb, resource string
	if spec.ResourceAttributes != nil {
		namespace = spec.ResourceAttributes.Namespace
		verb = spec.ResourceAttributes.Verb
		resource = spec.ResourceAttributes.Resource
		sub := spec.ResourceAttributes.Subresource
		if sub != "" {
			resource = fmt.Sprintf("%s.%s", resource, sub)
		}
	} else {
		verb = spec.NonResourceAttributes.Verb
		resource = spec.NonResourceAttributes.Path
	}

	domain := d.DomainFromNamespace(namespace)
	identity := d.PrincipalFromUser(spec.User)

	switch {
	case inList(identity, d.DenyUsers):
		return "", nil, fmt.Errorf("'%s' is not authorized for any actions", identity)
	case inList(resource, d.DenyResources):
		return "", nil, fmt.Errorf("'%s' resources are not allowed through Athenz", resource)
	case !isReadAccess(verb) && inList(resource, d.AdminResources):
		old := domain
		domain = d.AdminDomain
		newRes := old + "." + resource
		resource = newRes
	}

	checks := []api.AthenzAccessCheck{
		{
			Resource: fmt.Sprintf("%s:%s", domain, resource),
			Action:   verb,
		},
	}
	// allow read access on namespaced resources based on access to the admin domain
	if domain != d.AdminDomain && isReadAccess(verb) {
		checks = append(checks, api.AthenzAccessCheck{
			Resource: fmt.Sprintf("%s:%s", d.AdminDomain, resource),
			Action:   verb,
		})
	}
	return identity, checks, nil
}

// FileToken provides an IdentityToken implementation by loading the service ntoken from
// a file and reloading it every so often.
type FileToken struct {
	tokenPath string
	validate  bool
	stop      chan struct{}
	l         sync.RWMutex
	current   string
	err       error
}

// NewLogProvider returns a log provider using the log stdlib package.
func NewLogProvider(w io.Writer) api.LogProvider {
	return func(requestID string) api.Logger {
		return log.New(w, fmt.Sprintf("[%s] ", requestID), log.LstdFlags)
	}
}

// NewFileToken provides an IdentityToken implementation.
func NewFileToken(file string, validateToken bool, refresh time.Duration) (*FileToken, error) {
	ft := &FileToken{
		tokenPath: file,
		validate:  validateToken,
		stop:      make(chan struct{}, 1),
	}
	tok, err := ft.load()
	if err != nil {
		return nil, err
	}
	ft.set(tok, nil)
	go ft.poll(refresh)
	return ft, nil
}

// TokenValue implements the IdentityToken interface.
func (f *FileToken) TokenValue() (string, error) {
	f.l.RLock()
	defer f.l.RUnlock()
	return f.current, f.err
}

func (f *FileToken) set(tok string, err error) {
	f.l.Lock()
	defer f.l.Unlock()
	f.current = tok
	f.err = err
}

func (f *FileToken) load() (string, error) {
	b, err := ioutil.ReadFile(f.tokenPath)
	if err != nil {
		return "", err
	}
	tok := strings.TrimRight(string(b), "\r\n")
	if f.validate {
		err := api.VerifyToken(tok, false)
		if err != nil {
			return "", fmt.Errorf("invalid server identity token from %s: %v", f.tokenPath, err)
		}
	}
	return tok, nil
}

func (f *FileToken) poll(refresh time.Duration) {
	if refresh == 0 {
		return
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.set(f.load()) // XXX: make more efficient if needed
		case <-f.stop:
			return
		}
	}
}

// Close stops all background processing.
func (f *FileToken) Close() error {
	select {
	case f.stop <- struct{}{}:
	default:
	}
	return nil
}
