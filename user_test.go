package tumoidc

import (
	"testing"
)

func TestUserInfo_HasRequiredRole(t *testing.T) {
	tests := []struct {
		name          string
		userRoles     []string
		requiredRoles []string
		expected      bool
	}{
		{
			name:          "user has required role",
			userRoles:     []string{"admin", "user"},
			requiredRoles: []string{"admin"},
			expected:      true,
		},
		{
			name:          "user has one of multiple required roles",
			userRoles:     []string{"editor", "user"},
			requiredRoles: []string{"admin", "editor"},
			expected:      true,
		},
		{
			name:          "user does not have required role",
			userRoles:     []string{"user"},
			requiredRoles: []string{"admin"},
			expected:      false,
		},
		{
			name:          "user has no roles",
			userRoles:     []string{},
			requiredRoles: []string{"admin"},
			expected:      false,
		},
		{
			name:          "no required roles",
			userRoles:     []string{"admin"},
			requiredRoles: []string{},
			expected:      false,
		},
		{
			name:          "empty roles and requirements",
			userRoles:     []string{},
			requiredRoles: []string{},
			expected:      false,
		},
		{
			name:          "case sensitive role matching",
			userRoles:     []string{"Admin"},
			requiredRoles: []string{"admin"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := UserInfo{Roles: tt.userRoles}
			result := user.HasRequiredRole(tt.requiredRoles...)
			if result != tt.expected {
				t.Errorf("HasRequiredRole() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
