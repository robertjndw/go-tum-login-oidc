package tumoidc

import (
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Issuer       string
}

func (o *Options) validate() error {
	if o.ClientID == "" {
		return errors.New("client ID is required")
	}
	if o.RedirectURL == "" {
		return errors.New("redirect URL is required")
	}
	// Set defaults
	if o.Issuer == "" {
		o.Issuer = tumLiveLogin
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{oidc.ScopeOpenID}
	}

	return nil
}
