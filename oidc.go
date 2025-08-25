package tumoidc

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	tumLiveLogin = "https://login.tum.de"
)

type TUMOIDC struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

func New(ctx context.Context, opts Options) (*TUMOIDC, error) {
	if opts.ClientID == "" {
		return nil, errors.New("client ID is required")
	}

	if opts.RedirectURL == "" {
		return nil, errors.New("redirect URL is required")
	}

	provider, err := oidc.NewProvider(ctx, tumLiveLogin)
	if err != nil {
		return nil, err
	}

	total_scopes := []string{oidc.ScopeOpenID}
	total_scopes = append(total_scopes, opts.Scopes...)

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  opts.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: total_scopes,
	}

	return &TUMOIDC{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		oauth2:   &oauth2Config,
	}, nil
}

func (t *TUMOIDC) AuthCodeURL(state, codeChallenge string) string {
	return t.oauth2.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
