package tumoidc

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	defaultSessionKey = "oidc-session"
)

type HTTPHandler struct {
	OIDCClient   *TUMOIDC
	SessionStore sessions.Store
	SessionName  string // Name of the session cookie
}

// NewHTTPHandler creates a new HTTPHandler with the given session store
func NewHTTPHandler(oidcClient *TUMOIDC, store sessions.Store) *HTTPHandler {
	return &HTTPHandler{
		OIDCClient:   oidcClient,
		SessionStore: store,
		SessionName:  defaultSessionKey,
	}
}

func (h *HTTPHandler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get session: %w", err))
			return
		}
		// OR if you want to use your custom store:
		// session := h.SessionStore.Get(r, h.SessionName)

		// Generate PKCE parameters
		pkce, err := h.OIDCClient.GeneratePKCE()
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to generate PKCE: %w", err))
			return
		}

		// Store PKCE data in session
		session.Values["code_verifier"] = pkce.CodeVerifier
		session.Values["state"] = pkce.State

		// Store the original URL to redirect after login
		if returnURL := r.URL.Query().Get("return_url"); returnURL != "" {
			session.Values["return_url"] = returnURL
		}

		// Persist session data with error checking
		if err := session.Save(r, w); err != nil {
			handleError(w, r, fmt.Errorf("failed to save session: %w", err))
			return
		}

		authURL := h.OIDCClient.AuthCodeURL(pkce.State, pkce.CodeChallenge)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func (h *HTTPHandler) HandleCallback(w http.ResponseWriter, r *http.Request) (UserInfo, error) {
	ctx := r.Context()

	// Get session for this specific request
	session, err := h.SessionStore.Get(r, h.SessionName)
	if err != nil {
		return UserInfo{}, err
	}
	// OR: session := h.SessionStore.Get(r, h.SessionName)

	// Check for error in callback
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		err := fmt.Errorf("OIDC error: %s - %s", errMsg, errDesc)
		return UserInfo{}, err
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		return UserInfo{}, fmt.Errorf("missing authorization code")
	}

	// Verify state
	storedState := session.Values["state"]
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to get stored state: %w", err)
	}
	if storedState != state {
		return UserInfo{}, fmt.Errorf("invalid state parameter")
	}

	// Get code verifier
	codeVerifierRaw := session.Values["code_verifier"]
	if codeVerifierRaw == nil {
		return UserInfo{}, fmt.Errorf("failed to get code verifier")
	}
	codeVerifier, ok := codeVerifierRaw.(string)
	if !ok {
		return UserInfo{}, fmt.Errorf("invalid code verifier in session")
	}

	// Exchange code for token using PKCE
	token, err := h.OIDCClient.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return UserInfo{}, fmt.Errorf("no ID token received")
	}

	// Verify ID token
	idToken, err := h.OIDCClient.VerifyIDToken(ctx, rawIDToken)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract user information
	userInfo, err := ExtractUserInfo(idToken)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to extract user information: %w", err)
	}

	session.Values["user"] = userInfo

	// Clean up temporary session data
	delete(session.Values, "code_verifier")
	delete(session.Values, "state")

	session.Save(r, w)

	return *userInfo, nil
}

func (h *HTTPHandler) LogOut() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get session: %w", err))
			return
		}

		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Save(r, w)
	}
}

// RequireAuth is a middleware that requires authentication
func (h *HTTPHandler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireRoles(next)
}

// RequireAuth is a middleware that requires authentication
func (h *HTTPHandler) RequireRoles(next http.HandlerFunc, requiredRoles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get session: %w", err))
			return
		}

		user, ok := session.Values["user"].(UserInfo)
		if !ok || user.Sub == "" {
			// User is not authenticated, redirect to login
			h.Login()(w, r)
			return
		}

		// Check for required roles if they are specified
		if len(requiredRoles) > 0 && !user.HasRequiredRole(requiredRoles...) {
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		// Add user to request context for easy access in handlers
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
