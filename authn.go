package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	authn "k8s.io/api/authentication/v1"
)

const (
	authnSupportedVersion = "authentication.k8s.io/v1"
	authnSupportedKind    = "TokenReview"
)

type authenticator struct {
	AuthenticationConfig
}

func newAuthn(c AuthenticationConfig) *authenticator {
	return &authenticator{
		AuthenticationConfig: c,
	}
}

// getTokenReview extracts the token review object from the request and returns it.
func (a *authenticator) getTokenReview(ctx context.Context, req *http.Request) (*authn.TokenReview, error) {
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("body read error for authentication request, %v", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty body for authentication request")
	}
	if isLogEnabled(ctx, LogTraceServer) {
		getLogger(ctx).Printf("request body: %s\n", b)
	}
	var r authn.TokenReview
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON request '%s', %v", b, err)
	}

	if r.APIVersion != authnSupportedVersion {
		return nil, fmt.Errorf("unsupported authentication version, want '%s', got '%s'", authnSupportedVersion, r.APIVersion)
	}
	if r.Kind != authnSupportedKind {
		return nil, fmt.Errorf("unsupported authentication kind, want '%s', got '%s'", authnSupportedKind, r.Kind)
	}
	if r.Spec.Token == "" {
		return nil, fmt.Errorf("empty authentication token spec. Must set a token value")
	}
	return &r, nil
}

func (a *authenticator) deny(err error) (ts *authn.TokenReviewStatus) {
	return &authn.TokenReviewStatus{
		Authenticated: false,
		Error:         err.Error(),
	}
}

func (a *authenticator) getNToken(tok string) (*ntoken, error) {
	nt, err := newNToken(tok)
	if err != nil {
		return nil, err
	}
	return nt, nt.checkExpiry()
}

func (a *authenticator) authenticate(ctx context.Context, nt *ntoken) (ts *authn.TokenReviewStatus) {
	log := getLogger(ctx)
	xp := newAuthTransport(a.AuthHeader, nt.raw)
	if isLogEnabled(ctx, LogTraceAthenz) {
		xp = &debugTransport{
			RoundTripper: xp,
			log:          log,
		}
	}

	var u authn.UserInfo
	token, err := a.Validator.Validate(nt.raw)
	if err != nil && strings.Contains(err.Error(), "Unable to get public key from ZTS") {
		log.Println("Validation of ntoken failed:", err)
		log.Println("Retrying validation against the zms principal endpoint.")

		var p *AthenzPrincipal
		client := newClient(a.ZMSEndpoint, a.ZTSEndpoint, a.Timeout, xp)
		p, err = client.authenticate()
		if err != nil {
			return a.deny(err)
		}
		u, err = a.Mapper.MapUser(ctx, p.Domain, p.Service)
	} else if err != nil {
		return a.deny(err)
	} else {
		u, err = a.Mapper.MapUser(ctx, token.Domain, token.Name)
	}

	if err != nil {
		return a.deny(err)
	}

	return &authn.TokenReviewStatus{
		Authenticated: true,
		User:          u,
	}
}

func (a *authenticator) logOutcome(ctx context.Context, nt *ntoken, remoteAddr string, status *authn.TokenReviewStatus) {
	req := fmt.Sprintf("'%s' from %s", nt, remoteAddr)
	granted := "granted"
	var add string
	if !status.Authenticated {
		granted = "denied"
		add = "error=" + status.Error
	} else {
		u := status.User
		add = fmt.Sprintf("user=%s, uid=%s, groups=%v", u.Username, u.UID, u.Groups)
	}
	getLogger(ctx).Printf("authn %s %s -> %s\n", granted, req, add)
}

func (a *authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := getLogger(ctx)

	tr, err := a.getTokenReview(ctx, r)
	if err != nil {
		l.Printf("authn request error from %s: %v\n", r.RemoteAddr, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	nt, err := a.getNToken(tr.Spec.Token)
	var ts *authn.TokenReviewStatus
	if err != nil {
		ts = a.deny(err)
	} else {
		ts = a.authenticate(r.Context(), nt)
	}

	a.logOutcome(ctx, nt, r.RemoteAddr, ts)
	resp := struct {
		APIVersion string                   `json:"apiVersion"`
		Kind       string                   `json:"kind"`
		Status     *authn.TokenReviewStatus `json:"status"`
	}{tr.APIVersion, tr.Kind, ts}
	writeJSON(ctx, w, &resp)
}
