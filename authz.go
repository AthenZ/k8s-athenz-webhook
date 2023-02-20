package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	authz "k8s.io/api/authorization/v1"
)

const (
	authzSupportedVersion = "authorization.k8s.io/v1"
	authzSupportedKind    = "SubjectAccessReview"
)

// AuthzError is an error implementation that can provide custom
// messages for the reason field in the
// SubjectAccessReviewStatus object.
type AuthzError struct {
	error
	reason string
}

// NewAuthzError returns an error implementation whose reason
// member is copied into the returned status object.
func NewAuthzError(delegate error, reason string) *AuthzError {
	return &AuthzError{
		error:  delegate,
		reason: reason,
	}
}

// Reason returns the string that should be copied into the `reason`
// field of the status object.
func (a *AuthzError) Reason() string {
	return a.reason
}

type authorizer struct {
	AuthorizationConfig
}

func newAuthz(c AuthorizationConfig) *authorizer {
	return &authorizer{
		AuthorizationConfig: c,
	}
}

func (a *authorizer) client(ctx context.Context) (*client, error) {
	tok, err := a.Token()
	if err != nil {
		return nil, err
	}
	xp := newAuthTransport(a.AuthHeader, tok)
	if isLogEnabled(ctx, LogTraceAthenz) {
		xp = &debugTransport{
			log:          getLogger(ctx),
			RoundTripper: xp,
		}
	}
	return newClient(a.ZMSEndpoint, a.ZTSEndpoint, a.Timeout, xp), nil
}

// clientX509 returns the client set up with x509 cert and key to make calls to Athenz.
func (a *authorizer) clientX509(ctx context.Context) (*client, error) {

	config, err := a.AthenzX509()
	if err != nil {
		return nil, err
	}
	xpX509 := &http.Transport{
		TLSClientConfig: config,
	}

	debugXp := &debugTransport{}
	if isLogEnabled(ctx, LogTraceAthenz) {
		debugXp = &debugTransport{
			log:          getLogger(ctx),
			RoundTripper: xpX509,
		}
		return newClient(a.ZMSEndpoint, a.ZTSEndpoint, a.Timeout, debugXp), nil
	}
	return newClient(a.ZMSEndpoint, a.ZTSEndpoint, a.Timeout, xpX509), nil
}

// getSubjectAccessReview extracts the subject access review object from the request and returns it.
func (a *authorizer) getSubjectAccessReview(ctx context.Context, req *http.Request) (*authz.SubjectAccessReview, error) {
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("body read error for authorization request, %v", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty body for authorization request")
	}
	if isLogEnabled(ctx, LogTraceServer) {
		getLogger(ctx).Printf("request body: %s\n", b)
	}
	var r authz.SubjectAccessReview
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON request '%s', %v", b, err)
	}
	if r.APIVersion != authzSupportedVersion {
		return nil, fmt.Errorf("unsupported authorization version, want '%s', got '%s'", authzSupportedVersion, r.APIVersion)
	}
	if r.Kind != authzSupportedKind {
		return nil, fmt.Errorf("unsupported authorization kind, want '%s', got '%s'", authzSupportedKind, r.Kind)
	}
	if r.Spec.ResourceAttributes == nil && r.Spec.NonResourceAttributes == nil {
		return nil, fmt.Errorf("bad authorization spec, must have one of resource or non-resource attributes")
	}
	return &r, nil
}

// grantStatus adds extra information to a review status.
type grantStatus struct {
	status authz.SubjectAccessReviewStatus // the status to be returned to the client
	via    string                          // the resource check that succeeded for a grant, not set for deny
}

// useCacheEval - authorize using cache
func (a *authorizer) useCacheEval(log Logger, principal string, checks []AthenzAccessCheck) (*grantStatus, error) {
	var via string
	var decision bool
	var err error
	var errstrings []string
	var aggrError error
	for _, check := range checks {
		decision, err = a.AuthorizationConfig.Config.Cache.authorize(principal, check)
		if err != nil {
			errstrings = append(errstrings, fmt.Errorf("Error happened using cache to evaluate authorization decision: %s", err).Error())
			continue
		}
		if decision {
			via = check.String()
			break
		}
	}
	log.Println("Authorization decision using cache (true=authorized, false=not authorized): ", decision)
	if len(errstrings) > 0 {
		aggrError = fmt.Errorf(strings.Join(errstrings, "\n"))
	}
	if decision {
		return &grantStatus{
			status: authz.SubjectAccessReviewStatus{
				Allowed: true,
			},
			via: via,
		}, aggrError
	}
	return &grantStatus{
		status: authz.SubjectAccessReviewStatus{
			Allowed: false,
		},
		via: via,
	}, aggrError
}

func (a *authorizer) authorize(ctx context.Context, sr authz.SubjectAccessReviewSpec) *grantStatus {
	log := getLogger(ctx)
	deny := func(err error, addHelpText bool) *grantStatus {
		var reason string
		if e, ok := err.(*AuthzError); ok {
			reason = e.Reason()
		}
		if addHelpText {
			reason += a.HelpMessage
		}
		return &grantStatus{
			status: authz.SubjectAccessReviewStatus{
				Allowed:         false,
				Reason:          reason,
				EvaluationError: err.Error(),
			},
		}
	}
	principal, checks, err := a.Mapper.MapResource(ctx, sr)
	if err != nil {
		return deny(fmt.Errorf("mapping error: %v", err), true)
	}
	var granted bool
	if len(checks) == 0 { // grant it by API contract
		return &grantStatus{
			status: authz.SubjectAccessReviewStatus{
				Allowed: true,
			},
			via: "no Athenz resource checks needed",
		}
	}
	internal := "internal setup error."
	var via string
	var client *client
	var decision *grantStatus
	var cacheEvalError error
	if a.AuthorizationConfig.Config.UseCache {
		// check syncer's last contact time with athenz, if it is more than two hours,
		// fall back to zms/zts.
		a.AuthorizationConfig.Config.Cache.cmLock.RLock()
		status := a.AuthorizationConfig.Config.Cache.cacheStatus && a.AuthorizationConfig.Config.Cache.cacheEnabled
		a.AuthorizationConfig.Config.Cache.cmLock.RUnlock()
		if status {
			decision, cacheEvalError = a.useCacheEval(log, principal, checks)
			if decision.status.Allowed == true && !a.AuthorizationConfig.Config.DryRun {
				return decision
			}
		} else {
			log.Printf("Cache has not been updated for more than %v hours, last update time is: %v, failing back to zts/zms for authorization. ", a.AuthorizationConfig.Config.Cache.maxContactTime, a.AuthorizationConfig.Config.Cache.lastUpdate)
		}
	}
	for _, check := range checks {
		if a.AthenzClientAuthnx509Mode {
			client, err = a.clientX509(ctx)
		} else {
			client, err = a.client(ctx)
		}
		if err != nil {
			return deny(NewAuthzError(err, internal), true)
		}
		granted, err = client.authorize(ctx, principal, check)
		if err != nil {
			switch e := err.(type) {
			case *statusCodeError:
				switch e.code {
				case http.StatusBadRequest: // ResourceException. Not supported resource name
					return deny(NewAuthzError(fmt.Errorf("resource related error for %v, %v", check, err), fmt.Sprintf("Invalid ResourceName error.")), false)
				case http.StatusUnauthorized: // internal identity token was borked
					return deny(NewAuthzError(err, internal), true)
				case http.StatusNotFound: // domain setup error
					return deny(NewAuthzError(fmt.Errorf("domain related error for %v, %v", check, err), fmt.Sprintf("Athenz domain error.")), false)
				}
			}
			return deny(NewAuthzError(err, ""), true)
		}
		if granted {
			via = check.String()
			break
		}
	}

	// if cache and dry run are enabled, error need to be added to log if authorize result from cache and authorize result from zts / zms are different.
	// skip the check if decision is nil, decision will be nil if cache is out of sync with athenz
	if a.AuthorizationConfig.Config.UseCache && decision != nil {
		if decision.status.Allowed != granted {
			var viaCheck string
			if decision.via != "" {
				viaCheck = decision.via
			} else {
				viaCheck = via
			}
			log.Printf("There is a mismatch between cache result and zms result. Cache granted: %t, Athenz granted: %t for user: %s on check: %s", decision.status.Allowed, granted, principal, viaCheck)
			if cacheEvalError != nil {
				log.Printf("Error when using cache to authorize: %s", cacheEvalError)
			}
		}
	}

	if !granted {
		var list []string
		for _, c := range checks {
			list = append(list, fmt.Sprintf("'%s'", c))
		}
		msg := fmt.Sprintf("principal %s does not have access to any of %s resources", principal, strings.Join(list, ","))
		return deny(errors.New(msg), false) // not showing this msg to the user, should we?
	}
	return &grantStatus{
		status: authz.SubjectAccessReviewStatus{
			Allowed: true,
		},
		via: via,
	}
}

func (a *authorizer) logOutcome(logger Logger, sr *authz.SubjectAccessReviewSpec, gs *grantStatus) {
	srText := "unknown"
	switch {
	case sr.ResourceAttributes != nil:
		ra := sr.ResourceAttributes
		srText = fmt.Sprintf("%s: %s on %s:%s:%s:%s", sr.User, ra.Verb, ra.Namespace, ra.Resource, ra.Subresource, ra.Name)
	case sr.NonResourceAttributes != nil:
		nra := sr.NonResourceAttributes
		srText = fmt.Sprintf("%s: %s on %s", sr.User, nra.Verb, nra.Path)
	}

	var srDebug string
	b, err := json.Marshal(sr)
	if err == nil {
		srDebug = " (" + string(b) + ")"
	}
	granted := "granted"
	status := gs.status
	if !status.Allowed {
		granted = "denied"
	}
	var add string
	if gs.via != "" {
		add += "via " + gs.via
	}
	if status.EvaluationError != "" {
		add += "error:" + status.EvaluationError
		if status.Reason != "" {
			add += ", reason:" + status.Reason
		}
	}
	logger.Printf("authz %s %s -> %s%s\n", granted, srText, add, srDebug)
}

func (a *authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sr, err := a.getSubjectAccessReview(ctx, r)
	if err != nil {
		getLogger(ctx).Printf("authz request error from %s: %v\n", r.RemoteAddr, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	gs := a.authorize(ctx, sr.Spec)
	a.logOutcome(getLogger(ctx), &sr.Spec, gs)

	resp := struct {
		APIVersion string                          `json:"apiVersion"`
		Kind       string                          `json:"kind"`
		Status     authz.SubjectAccessReviewStatus `json:"status"`
	}{sr.APIVersion, sr.Kind, gs.status}
	writeJSON(ctx, w, &resp)
}
