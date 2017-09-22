package webhook

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	keyDomain     = "d"
	keyName       = "n"
	keySignature  = "s"
	keyExpiration = "e"
)

type ntoken struct {
	raw        string
	expiration time.Time
	attrs      map[string]string
}

func (n *ntoken) domain() string    { return n.attrs[keyDomain] }
func (n *ntoken) name() string      { return n.attrs[keyName] }
func (n *ntoken) signature() string { return n.attrs[keySignature] }
func (n *ntoken) String() string    { return n.domain() + "." + n.name() }

func (n *ntoken) assertValid() error {
	if n.domain() == "" {
		return fmt.Errorf("no domain in token")
	}
	if n.name() == "" {
		return fmt.Errorf("no name in token")
	}
	if n.signature() == "" {
		return fmt.Errorf("no signature in token")
	}
	return nil
}

func (n *ntoken) checkExpiry() error {
	e, ok := n.attrs[keyExpiration]
	if !ok {
		return fmt.Errorf("no expiration in token")
	}
	parsed, err := strconv.ParseInt(e, 0, 64)
	if err != nil {
		return fmt.Errorf("bad expiration in token, '%s'", e)
	}
	t := time.Unix(parsed, 0)
	n.expiration = t
	if n.expiration.Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}
	return nil
}

// newNToken returns an ntoken from the input string only if it is valid.
func newNToken(input string) (*ntoken, error) {
	attrs := map[string]string{}
	fields := strings.Split(input, ";")
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad field in token '%s'", field)
		}
		attrs[parts[0]] = parts[1]
	}
	nt := &ntoken{
		raw:   input,
		attrs: attrs,
	}
	if err := nt.assertValid(); err != nil {
		return nil, err
	}
	return nt, nil
}
