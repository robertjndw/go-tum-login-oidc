package tumoidc

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"
)

type HTTPHandler struct {
	OIDCClient     *TUMOIDC
	SessionManager *scs.SessionManager
}

// NewHTTPHandler creates a new HTTPHandler with the given session store
// NewHTTPHandler creates a new HTTPHandler with the given session store
func NewHTTPHandler(oidcClient *TUMOIDC) *HTTPHandler {
	return NewHTTPHandlerWithSessionName(oidcClient, "tum_oidc_session")
}

// NewHTTPHandlerWithSessionName creates a new HTTPHandler with a custom session name
func NewHTTPHandlerWithSessionName(oidcClient *TUMOIDC, sessionName string) *HTTPHandler {
	sessionManager := scs.New()
	sessionManager.Cookie.Name = sessionName
	sessionManager.Cookie.Secure = true
	sessionManager.Cookie.SameSite = http.SameSiteStrictMode

	return &HTTPHandler{
		OIDCClient:     oidcClient,
		SessionManager: sessionManager,
	}
}

func (h *HTTPHandler) RegisterDefaultRoutes(mux *http.ServeMux) {
	mux.Handle("/login", h.Login())
	mux.Handle("/callback", h.HandleCallback(func(w http.ResponseWriter, r *http.Request, ui *UserInfo) {
		// Default behavior: just log the user info
		fmt.Printf("User %s authenticated successfully\n", ui.Sub)

		http.Redirect(w, r, "/", http.StatusFound)
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
			handleError(w, r, fmt.Errorf("failed to generate PKCE: %w", err), http.StatusInternalServerError)
			return
		}

		// Store PKCE data in session
		h.SessionManager.Put(ctx, "code_verifier", pkce.CodeVerifier)
		h.SessionManager.Put(ctx, "state", pkce.State)

		nonce, err := generateRandomString(32)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to generate nonce: %w", err), http.StatusInternalServerError)
			return
		}
		h.SessionManager.Put(ctx, "nonce", nonce)

		authURL := h.OIDCClient.AuthCodeURL(pkce.State, pkce.CodeChallenge, nonce)
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func (h *HTTPHandler) HandleCallback(fn func(http.ResponseWriter, *http.Request, *UserInfo)) http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check for error in callback
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			err := fmt.Errorf("OIDC error: %s - %s", sanitizeParam(errMsg), sanitizeParam(errDesc))
			handleError(w, r, err, http.StatusBadRequest)
			return
		}

		// Get authorization code and state
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			handleError(w, r, fmt.Errorf("missing authorization code"), http.StatusBadRequest)
			return
		}

		// Verify state
		storedState := h.SessionManager.PopString(ctx, "state")
		if storedState == "" || storedState != state {
			handleError(w, r, fmt.Errorf("invalid state parameter"), http.StatusBadRequest)
			return
		}

		// Get code verifier
		codeVerifier := h.SessionManager.PopString(ctx, "code_verifier")
		if codeVerifier == "" {
			handleError(w, r, fmt.Errorf("invalid code verifier in session"), http.StatusBadRequest)
			return
		}

		// Get Nonce
		nonceStr := h.SessionManager.PopString(ctx, "nonce")
		if nonceStr == "" {
			handleError(w, r, fmt.Errorf("invalid nonce in session"), http.StatusBadRequest)
			return
		}

		// Exchange code for token using PKCE
		token, err := h.OIDCClient.ExchangeCode(ctx, code, codeVerifier)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to exchange code for token: %w", err), http.StatusBadGateway)
			return
		}

		// Extract ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			handleError(w, r, fmt.Errorf("no ID token received"), http.StatusBadGateway)
			return
		}

		// Verify ID token
		_, err = h.OIDCClient.VerifyIDToken(ctx, rawIDToken, nonceStr)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to verify ID token: %w", err), http.StatusBadRequest)
			return
		}

		// Extract user information
		oidcUserInfo, err := h.OIDCClient.UserInfo(ctx, token)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to get userinfo: %w", err), http.StatusBadGateway)
			return
		}

		userInfo, err := ExtractUserInfo(oidcUserInfo)
		if err != nil {
			handleError(w, r, fmt.Errorf("failed to extract user information: %w", err), http.StatusInternalServerError)
			return
		}

		// Call authentication callback if set
		fn(w, r, userInfo)
	})
}

func (h *HTTPHandler) Logout() http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		if err := h.SessionManager.Destroy(r.Context()); err != nil {
			handleError(w, r, fmt.Errorf("failed to destroy session: %w", err), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func handleError(w http.ResponseWriter, r *http.Request, err error, status int) {
	log.Printf("ERROR [%s %s]: %v", r.Method, r.URL.Path, err)
	http.Error(w, "An authentication error occurred", status)
}

// sanitizeParam removes control characters from a string to prevent log injection.
func sanitizeParam(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
