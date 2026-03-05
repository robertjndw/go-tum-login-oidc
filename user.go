package tumoidc

import (
	"encoding/gob"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

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
	if oidcUserInfo == nil {
		return nil, fmt.Errorf("oidcUserInfo is nil")
	}
	var userInfo UserInfo
	if err := oidcUserInfo.Claims(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to extract userinfo claims: %w", err)
	}
	if userInfo.Sub == "" {
		return nil, fmt.Errorf("missing required 'sub' claim")
	}
	return &userInfo, nil
}
