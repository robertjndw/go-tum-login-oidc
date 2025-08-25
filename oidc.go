package tumoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

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

func New(ctx context.Context, opts Options) (*TUMOIDC, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, opts.Issuer)
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

// ExchangeCode exchanges the authorization code for tokens using PKCE
func (t *TUMOIDC) ExchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	token, err := t.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return token, nil
}

// VerifyIDToken verifies and parses the ID token
func (t *TUMOIDC) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := t.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}
	return idToken, nil
}

// PKCEData holds PKCE challenge and verifier
type PKCEData struct {
	CodeVerifier  string
	CodeChallenge string
	State         string
}

// GeneratePKCE generates PKCE code verifier and challenge
func (t *TUMOIDC) GeneratePKCE() (*PKCEData, error) {
	// Generate code verifier
	codeVerifier, err := generateRandomString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Generate code challenge using S256 method
	h := sha256.Sum256([]byte(codeVerifier[:128]))
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:])

	// Generate state
	state, err := generateRandomString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	return &PKCEData{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		State:         state,
	}, nil
}

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
