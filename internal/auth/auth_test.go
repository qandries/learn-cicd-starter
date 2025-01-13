package auth

import (
	"errors"
	"net/http"
	"testing"
)

var ErrMalformedAuthHeader = errors.New("malformed authorization header")

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{name: "Valid", header: http.Header{"Authorization": []string{"ApiKey myApiKey"}}, wantKey: "myApiKey", wantErr: nil},
		{name: "Malformed", header: http.Header{"Authorization": []string{"Bearer token"}}, wantKey: "", wantErr: ErrMalformedAuthHeader},
		{name: "Invalid", header: http.Header{}, wantKey: "", wantErr: ErrNoAuthHeaderIncluded},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotError := GetAPIKey(tc.header)
			if gotKey != tc.wantKey {
				t.Errorf("expected key: %q, got: %q", tc.wantKey, gotKey)
			}
			if (gotError == nil && tc.wantErr != nil) || (gotError != nil && tc.wantErr == nil) || (gotError != nil && tc.wantErr != nil && gotError.Error() != tc.wantErr.Error()) {
				t.Errorf("expected error: %q, got: %q", tc.wantErr, gotError)
			}
		})
	}
}
