package tumoidc

import (
	"fmt"
	"net/http"
	"net/url"

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

func (h *HTTPHandler) RegisterDefaultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", h.Login())
	mux.HandleFunc("/callback", h.HandleCallback())
	mux.HandleFunc("/logout", h.LogOut())
}

func (h *HTTPHandler) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get session: %w", err))
			return
		}
		// Store return URL from query parameter if provided
		returnURL := r.URL.Query().Get("return_url")
		if returnURL != "" {
			// Validate and sanitize return URL
			if parsedURL, err := url.Parse(returnURL); err == nil {
				// Only allow relative URLs or same-origin URLs for security
				if parsedURL.IsAbs() {
					if parsedURL.Host != r.Host {
						returnURL = "" // Reset for external URLs
					}
				}
			} else {
				returnURL = "" // Reset for invalid URLs
			}
			if returnURL != "" {
				session.Values["return_url"] = returnURL
			}
		}

		// Generate PKCE parameters
		pkce, err := h.OIDCClient.GeneratePKCE()
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to generate PKCE: %w", err))
			return
		}

		// Store PKCE data in session
		session.Values["code_verifier"] = pkce.CodeVerifier
		session.Values["state"] = pkce.State

		// Persist session data with error checking
		if err := session.Save(r, w); err != nil {
			handleError(w, r, fmt.Errorf("failed to save session: %w", err))
			return
		}

		authURL := h.OIDCClient.AuthCodeURL(pkce.State, pkce.CodeChallenge)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func (h *HTTPHandler) HandleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get session: %w", err))
			return
		}
		// OR: session := h.SessionStore.Get(r, h.SessionName)

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
		storedState := session.Values["state"]
		if storedState == nil {
			handleError(w, r, fmt.Errorf("failed to get stored state: %w", err))
			return
		}
		if storedState != state {
			handleError(w, r, fmt.Errorf("invalid state parameter"))
			return
		}

		// Get code verifier
		codeVerifierRaw := session.Values["code_verifier"]
		if codeVerifierRaw == nil {
			handleError(w, r, fmt.Errorf("failed to get code verifier"))
			return
		}
		codeVerifier, ok := codeVerifierRaw.(string)
		if !ok {
			handleError(w, r, fmt.Errorf("invalid code verifier in session"))
			return
		}

		// Exchange code for token using PKCE
		token, err := h.OIDCClient.ExchangeCode(ctx, code, codeVerifier)
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
		idToken, err := h.OIDCClient.VerifyIDToken(ctx, rawIDToken)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to verify ID token: %w", err))
			return
		}

		// Extract user information
		userInfo, err := ExtractUserInfo(idToken)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to extract user information: %w", err))
			return
		}

		session.Values["user"] = userInfo

		// Get return URL before cleaning up session data
		returnURL, _ := session.Values["return_url"].(string)
		if returnURL == "" {
			returnURL = "/"
		}

		// Clean up temporary session data
		delete(session.Values, "code_verifier")
		delete(session.Values, "state")
		delete(session.Values, "return_url")

		session.Save(r, w)

		// Add user to request context for easy access in handlers
		ctx = NewContextWithUser(ctx, userInfo)
		http.Redirect(w, r.WithContext(ctx), returnURL, http.StatusFound)
	}
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

// RequireRoles is a middleware that checks for required roles
func (h *HTTPHandler) RequireRoles(next http.HandlerFunc, requiredRoles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		return_url := r.URL.String()
		// Get session for this specific request
		session, err := h.SessionStore.Get(r, h.SessionName)
		if err != nil {
			q := r.URL.Query()
			q.Set("return_url", return_url)
			r.URL.RawQuery = q.Encode()
			h.Login()(w, r)
			return
		}

		user, ok := session.Values["user"].(UserInfo)
		if !ok || user.Sub == "" {
			// User is not authenticated, redirect to login
			q := r.URL.Query()
			q.Set("return_url", return_url)
			r.URL.RawQuery = q.Encode()
			h.Login()(w, r)
			return
		}

		// Check for required roles if they are specified
		if len(requiredRoles) > 0 && !user.HasRequiredRole(requiredRoles...) {
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		// Add user to request context for easy access in handlers
		ctx := NewContextWithUser(r.Context(), &user)
		next(w, r.WithContext(ctx))
	}
}

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
