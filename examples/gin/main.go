package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	tumoidc "github.com/robertjndw/go-tum-login-oidc"
)

func main() {
	// Initialize OIDC client
	oidcClient, err := tumoidc.New(context.Background(), tumoidc.Options{
		ClientID:    os.Getenv("TUM_CLIENT_ID"),
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"profile", "email"},
	})
	if err != nil {
		log.Fatal("Failed to create OIDC client:", err)
	}

	// Setup session store
	store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

	// Create HTTP handler
	handler := tumoidc.NewHTTPHandler(oidcClient, store)

	r := gin.Default()
	r.GET("/login", gin.WrapF(handler.Login()))
	r.GET("/callback", gin.WrapF(handler.HandleCallback()))
	r.GET("/logout", gin.WrapF(handler.LogOut()))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
