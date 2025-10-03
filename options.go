package tumoidc

import (
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Option func(*options)

func WithClientSecret(clientSecret string) Option {
	return func(o *options) {
		o.ClientSecret = clientSecret
	}
}

func WithRedirectURL(redirectURL string) Option {
	return func(o *options) {
		o.RedirectURL = redirectURL
	}
}

func WithScopes(scopes ...string) Option {
	return func(o *options) {
		o.Scopes = append(o.Scopes, scopes...)
	}
}

func WithIssuer(issuer string) Option {
	return func(o *options) {
		if issuer == "" {
			o.Issuer = tumLiveLogin
		}
	}
}

type options struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Issuer       string
}

func newOptions(clientID string) *options {
	return &options{
		ClientID: clientID,
		Scopes:   []string{oidc.ScopeOpenID},
		Issuer:   tumLiveLogin,
	}
}

func (o *options) validate() error {
	if o.ClientID == "" {
		return errors.New("client ID is required")
	}
	if o.RedirectURL == "" {
		return errors.New("redirect URL is required")
	}

	return nil
}
