package tumoidc

import (
	"testing"
)

func TestOptions_validate(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options with all fields",
			options: Options{
				ClientID:     "test-client-id",
				ClientSecret: "test-secret",
				RedirectURL:  "https://example.com/callback",
				Scopes:       []string{"profile", "email"},
				Issuer:       "https://custom-issuer.com",
			},
			wantErr: false,
		},
		{
			name: "missing client ID",
			options: Options{
				ClientSecret: "test-secret",
				RedirectURL:  "https://example.com/callback",
			},
			wantErr: true,
			errMsg:  "client ID is required",
		},
		{
			name: "missing redirect URL",
			options: Options{
				ClientID:     "test-client-id",
				ClientSecret: "test-secret",
			},
			wantErr: true,
			errMsg:  "redirect URL is required",
		},
		{
			name: "sets default issuer",
			options: Options{
				ClientID:    "test-client-id",
				RedirectURL: "https://example.com/callback",
			},
			wantErr: false,
		},
		{
			name: "sets default scopes",
			options: Options{
				ClientID:    "test-client-id",
				RedirectURL: "https://example.com/callback",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Options.validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Options.validate() error = %v, want %v", err.Error(), tt.errMsg)
			}
			if !tt.wantErr {
				// Check defaults are set
				if tt.options.Issuer == "" {
					t.Errorf("Expected default issuer to be set")
				}
				if len(tt.options.Scopes) == 0 {
					t.Errorf("Expected default scopes to be set")
				}
			}
		})
	}
}
