package tumoidc

import (
	"context"
	"encoding/gob"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type contextKey string

const userContextKey contextKey = "user"

type UserInfo struct {
	Sub                  string   `json:"sub"`
	Name                 string   `json:"name"`
	GivenName            string   `json:"given_name"`
	FamilyName           string   `json:"family_name"`
	UserName             string   `json:"preferred_username"`
	EduPersonAffiliation []string `json:"eduPersonAffiliation,omitempty"`
}

func init() {
	// Register UserInfo type for gob encoding/decoding
	gob.Register(UserInfo{})
}

func ExtractUserInfo(oidcUserInfo *oidc.UserInfo) (*UserInfo, error) {
	var userInfo UserInfo
	if err := oidcUserInfo.Claims(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to extract userinfo claims: %w", err)
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
