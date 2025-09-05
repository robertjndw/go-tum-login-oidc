package tumoidc

import (
	"fmt"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

type HTTPHandler struct {
	OIDCClient     *TUMOIDC
	SessionManager *scs.SessionManager
}

// NewHTTPHandler creates a new HTTPHandler with the given session store
func NewHTTPHandler(oidcClient *TUMOIDC) *HTTPHandler {
	return &HTTPHandler{
		OIDCClient:     oidcClient,
		SessionManager: scs.New(),
	}
}

func (h *HTTPHandler) RegisterDefaultRoutes(mux *http.ServeMux) {
	mux.Handle("/login", h.Login())
	mux.Handle("/callback", h.HandleCallback(func(ui *UserInfo) error {
		// Default behavior: just log the user info
		fmt.Printf("User %s authenticated successfully\n", ui.Sub)
		return nil
	}))
	mux.Handle("/logout", h.Logout())
}

func (h *HTTPHandler) loadAndSaveSession(f http.HandlerFunc) http.Handler {
	return h.SessionManager.LoadAndSave(http.HandlerFunc(f))
}

func (h *HTTPHandler) Login() http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Generate PKCE parameters
		pkce, err := h.OIDCClient.GeneratePKCE()
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to generate PKCE: %w", err))
			return
		}

		// Store PKCE data in session
		h.SessionManager.Put(ctx, "code_verifier", pkce.CodeVerifier)
		h.SessionManager.Put(ctx, "state", pkce.State)

		nonce, err := generateRandomString(32)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to generate nonce: %w", err))
			return
		}
		h.SessionManager.Put(ctx, "nonce", nonce)

		authURL := h.OIDCClient.AuthCodeURL(pkce.State, pkce.CodeChallenge, nonce)
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func (h *HTTPHandler) HandleCallback(fn func(*UserInfo) error) http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check for error in callback
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("OIDC error: %s - %s", errMsg, errDesc)
			handleError(w, r, err)
			return
		}

		// Get authorization code and state
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			handleError(w, r, fmt.Errorf("missing authorization code"))
			return
		}

		// Verify state
		storedState := h.SessionManager.PopString(ctx, "state")
		if storedState == "" || storedState != state {
			handleError(w, r, fmt.Errorf("invalid state parameter"))
			return
		}

		// Get code verifier
		codeVerifier := h.SessionManager.PopString(ctx, "code_verifier")
		if codeVerifier == "" {
			handleError(w, r, fmt.Errorf("invalid code verifier in session"))
			return
		}

		// Get Nonce
		nonceStr := h.SessionManager.PopString(ctx, "nonce")
		if nonceStr == "" {
			handleError(w, r, fmt.Errorf("invalid nonce in session"))
			return
		}

		// Exchange code for token using PKCE
		token, err := h.OIDCClient.ExchangeCode(ctx, code, codeVerifier, nonceStr)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to exchange code for token: %w", err))
			return
		}

		// Extract ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			handleError(w, r, fmt.Errorf("no ID token received"))
			return
		}

		// Verify ID token
		_, err = h.OIDCClient.VerifyIDToken(ctx, rawIDToken)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to verify ID token: %w", err))
			return
		}

		// Extract user information
		oidc_userInfo, err := h.OIDCClient.UserInfo(ctx, token)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to extract user information: %w", err))
			return
		}

		userInfo, err := ExtractUserInfo(oidc_userInfo)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to extract user information: %w", err))
			return
		}

		// Call authentication callback if set
		err = fn(userInfo)
		if err != nil {
			handleError(w, r, fmt.Errorf("authentication callback failed: %w", err))
			return
		}
	})
}

func (h *HTTPHandler) Logout() http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		h.SessionManager.Destroy(r.Context())
	})
}

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
