# go-tum-login-oidc

A Go library for [TUM-Login](https://collab.dvb.bayern/spaces/TUMdocs/pages/646223637/TUM-Login+Single+Sign-on) OIDC authentication with PKCE support and ready-to-use HTTP handlers.

## Features
- **TUM-specific OIDC integration** with default configuration for TUM's identity provider
- **PKCE (Proof Key for Code Exchange)** support for enhanced security
- **Ready-to-use HTTP handlers** for login, callback, and logout flows
- **Session management** with secure state and nonce handling
- **Framework agnostic** with examples for standard `net/http` and Gin
- **User information extraction** with TUM-specific claims support

## Installation
```bash
go get github.com/robertjndw/go-tum-login-oidc
```

## Quick Start

### Basic HTTP Server
```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    
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
    
    http.Handle("/login", handler.Login())
    http.Handle("/callback", handler.HandleCallback(func(user *tumoidc.UserInfo) error {
        log.Printf("User authenticated: %s (%s)", user.Name, user.UserName)
        return nil
    }))
    http.Handle("/logout", handler.Logout())

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### With Gin Framework
```go
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
    oidcClient, err := tumoidc.New(context.Background(), tumoidc.Options{
        ClientID:    os.Getenv("TUM_CLIENT_ID"),
        RedirectURL: "http://localhost:8080/callback",
        Scopes:      []string{"profile", "email"},
    })
    if err != nil {
        log.Fatal("Failed to create OIDC client:", err)
    }

    handler := tumoidc.NewHTTPHandler(oidcClient)
    r := gin.Default()
    
    r.GET("/login", gin.WrapH(handler.Login()))
    r.GET("/callback", gin.WrapH(handler.HandleCallback(func(user *tumoidc.UserInfo) error {
        // Process authenticated user
        return nil
    })))
    r.GET("/logout", gin.WrapH(handler.Logout()))

    log.Fatal(http.ListenAndServe(":8080", r))
}
```

## Configuration

### Options
```go
type Options struct {
    ClientID     string   // Required: Your TUM OIDC client ID
    ClientSecret string   // Optional: Client secret (for confidential clients)
    RedirectURL  string   // Required: Callback URL after authentication
    Scopes       []string // Optional: Additional scopes (defaults to ["openid"])
    Issuer       string   // Optional: Custom issuer URL (defaults to TUM's issuer)
}
```

## User Information
The library extracts user information into a structured format:

```go
type UserInfo struct {
    Sub                  string   `json:"sub"`
    Name                 string   `json:"name"`
    GivenName            string   `json:"given_name"`
    FamilyName           string   `json:"family_name"`
    UserName             string   `json:"preferred_username"`
    EduPersonAffiliation []string `json:"eduPersonAffiliation,omitempty"`
}
```

## Advanced Usage

### Manual OIDC Flow
For more control over the authentication flow:

```go
// Generate PKCE parameters
pkce, err := oidcClient.GeneratePKCE()
if err != nil {
    // handle error
}

// Generate auth URL
authURL := oidcClient.AuthCodeURL(pkce.State, pkce.CodeChallenge, nonce)

// Later, exchange code for token
token, err := oidcClient.ExchangeCode(ctx, code, pkce.CodeVerifier, nonce)
if err != nil {
    // handle error
}

// Get user info
userInfo, err := oidcClient.UserInfo(ctx, token)
if err != nil {
    // handle error
}
```

## Security Features
- **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
- **State Parameter**: Prevents CSRF attacks during OAuth flow
- **Nonce Validation**: Protects against token replay attacks
- **Secure Sessions**: Uses cryptographically secure random generators
- **Token Verification**: Validates ID tokens and signatures

## Examples
See the [`examples/`](examples/) directory for complete working examples:
- [`examples/http/`](examples/http/) - Standard HTTP server
- [`examples/gin/`](examples/gin/) - Gin framework integration

Set environment variables for client ID and secret:
```bash
export TUM_CLIENT_ID="your-client-id"
export TUM_CLIENT_SECRET="your-client-secret"  # If using confidential client
```

Run the examples:
```bash
go run examples/http/main.go
# or
go run examples/gin/main.go
```

## Testing
Run the test suite:

```bash
go test ./...
```

## Requirements
- Go 1.23+
- [TUM-Login OIDC client registration](https://collab.dvb.bayern/spaces/TUMdocs/pages/645763130/Zugang+erhalten+SSO)

## License
This project is licensed under the MIT License.