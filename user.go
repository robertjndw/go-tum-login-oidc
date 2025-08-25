package tumoidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type contextKey string

const userContextKey contextKey = "user"

type UserInfo struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	Roles         []string `json:"roles,omitempty"`
}

func ExtractUserInfo(idToken *oidc.IDToken) (*UserInfo, error) {
	var userInfo UserInfo
	if err := idToken.Claims(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to extract user info: %w", err)
	}
	return &userInfo, nil
}

func NewContextWithUser(ctx context.Context, user *UserInfo) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func GetUserFromContext(ctx context.Context) (*UserInfo, bool) {
	user, ok := ctx.Value(userContextKey).(*UserInfo)
	return user, ok
}

func (u UserInfo) HasRequiredRole(requiredRoles ...string) bool {
	for _, userRole := range u.Roles {
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				return true
			}
		}
	}
	return false
}
