package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	tumoidc "github.com/robertjndw/go-tum-login-oidc"
)

func main() {
	// Initialize OIDC client
	oidcClient, err := tumoidc.New(context.Background(), os.Getenv("TUM_CLIENT_ID"),
		tumoidc.WithClientSecret(os.Getenv("TUM_CLIENT_SECRET")),
		tumoidc.WithRedirectURL("http://localhost:8080/callback"),
		tumoidc.WithScopes("profile", "email"),
	)
	if err != nil {
		log.Fatal("Failed to create OIDC client:", err)
	}

	// Create HTTP handler
	handler := tumoidc.NewHTTPHandler(oidcClient)

	r := gin.Default()
	r.GET("/login", gin.WrapH(handler.Login()))
	r.GET("/callback", gin.WrapH(handler.HandleCallback(func(w http.ResponseWriter, r *http.Request, user *tumoidc.UserInfo) {
		// Do something with the user information
		fmt.Println("User authenticated:", user)

		// Redirect to home page after successful login
		http.Redirect(w, r, "/", http.StatusFound)
	})))
	r.GET("/logout", gin.WrapH(handler.Logout()))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
