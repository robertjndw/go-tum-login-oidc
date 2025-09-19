package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	tumoidc "github.com/robertjndw/go-tum-login-oidc"
)

func main() {
	// Initialize OIDC client
	oidcClient, err := tumoidc.New(context.Background(), tumoidc.Options{
		ClientID:     os.Getenv("TUM_CLIENT_ID"),
		ClientSecret: os.Getenv("TUM_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"profile", "email"},
	})
	if err != nil {
		log.Fatal("Failed to create OIDC client:", err)
	}

	// Create HTTP handler
	handler := tumoidc.NewHTTPHandler(oidcClient)
	http.Handle("/login", handler.Login())
	// http.Handle("/callback", handler.HandleCallback())
	// More advanced with user information processing
	http.Handle("/callback", handler.HandleCallback(func(w http.ResponseWriter, r *http.Request, user *tumoidc.UserInfo) {
		// Do something with the user information
		fmt.Println("User authenticated:", user)

		// Redirect to home page after successful login
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	http.Handle("/logout", handler.Logout())

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
