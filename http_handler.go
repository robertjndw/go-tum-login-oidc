package tumoidc

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/alexedwards/scs/v2"
)

type HTTPHandler struct {
	OIDCClient      *TUMOIDC
	SessionManager  *scs.SessionManager
	onAuthenticated func(*UserInfo) error
}

// NewHTTPHandler creates a new HTTPHandler with the given session store
func NewHTTPHandler(oidcClient *TUMOIDC) *HTTPHandler {
	return &HTTPHandler{
		OIDCClient:     oidcClient,
		SessionManager: scs.New(),
	}
}

func (h *HTTPHandler) WithOnAuthenticated(fn func(*UserInfo) error) *HTTPHandler {
	// Create a new handler instance to avoid modifying the original
	newHandler := *h
	newHandler.onAuthenticated = fn
	return &newHandler
}

func (h *HTTPHandler) RegisterDefaultRoutes(mux *http.ServeMux) {
	mux.Handle("/login", h.Login())
	mux.Handle("/callback", h.HandleCallback())
	mux.Handle("/logout", h.Logout())
}

func (h *HTTPHandler) loadAndSaveSession(f http.HandlerFunc) http.Handler {
	return h.SessionManager.LoadAndSave(http.HandlerFunc(f))
}

func (h *HTTPHandler) Login() http.Handler {
	return h.loadAndSaveSession(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
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
				h.SessionManager.Put(ctx, "return_url", returnURL)
			}
		}

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

func (h *HTTPHandler) HandleCallback() http.Handler {
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
		if h.onAuthenticated != nil {
			if err := h.onAuthenticated(userInfo); err != nil {
				handleError(w, r, fmt.Errorf("authentication callback failed: %w", err))
				return
			}
		}

		// Get return URL before cleaning up session data
		returnURL := h.SessionManager.PopString(ctx, "return_url")
		if returnURL == "" {
			returnURL = "/"
		}

		h.SessionManager.Put(ctx, "user", *userInfo)

		fmt.Printf("User %s authenticated successfully\n", userInfo.Sub)

		http.Redirect(w, r, returnURL, http.StatusFound)
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
