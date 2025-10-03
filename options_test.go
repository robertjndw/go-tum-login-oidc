package tumoidc

import (
	"testing"
)

func TestOptions_validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *options
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options with all fields",
			setup: func() *options {
				opts := newOptions("test-client-id")
				WithClientSecret("test-secret")(opts)
				WithRedirectURL("https://example.com/callback")(opts)
				WithScopes("profile", "email")(opts)
				WithIssuer("https://custom-issuer.com")(opts)
				return opts
			},
			wantErr: false,
		},
		{
			name: "missing client ID",
			setup: func() *options {
				opts := newOptions("")
				WithClientSecret("test-secret")(opts)
				WithRedirectURL("https://example.com/callback")(opts)
				return opts
			},
			wantErr: true,
			errMsg:  "client ID is required",
		},
		{
			name: "missing redirect URL",
			setup: func() *options {
				opts := newOptions("test-client-id")
				WithClientSecret("test-secret")(opts)
				return opts
			},
			wantErr: true,
			errMsg:  "redirect URL is required",
		},
		{
			name: "sets default issuer",
			setup: func() *options {
				opts := newOptions("test-client-id")
				WithRedirectURL("https://example.com/callback")(opts)
				return opts
			},
			wantErr: false,
		},
		{
			name: "sets default scopes",
			setup: func() *options {
				opts := newOptions("test-client-id")
				WithRedirectURL("https://example.com/callback")(opts)
				return opts
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := tt.setup()
			err := options.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Options.validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Options.validate() error = %v, want %v", err.Error(), tt.errMsg)
			}
			if !tt.wantErr {
				// Check defaults are set
				if options.Issuer == "" {
					t.Errorf("Expected default issuer to be set")
				}
				if len(options.Scopes) == 0 {
					t.Errorf("Expected default scopes to be set")
				}
			}
		})
	}
}
