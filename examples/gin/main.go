package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
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

	// Create HTTP handler
	handler := tumoidc.NewHTTPHandler(oidcClient)

	r := gin.Default()
	r.GET("/login", gin.WrapH(handler.Login()))
	r.GET("/callback", gin.WrapH(handler.HandleCallback()))
	r.GET("/logout", gin.WrapH(handler.LogOut()))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
