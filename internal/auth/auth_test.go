package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedKey    string
		expectedError  error
		shouldError    bool
	}{
		{
			name:          "Valid API key",
			authHeader:    "ApiKey abc123xyz",
			expectedKey:   "abc123xyz",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name:          "Valid API key with complex value",
			authHeader:    "ApiKey sk-1234567890abcdef",
			expectedKey:   "sk-1234567890abcdef",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name:          "No authorization header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldError:   true,
		},
		{
			name:          "Malformed header - wrong prefix",
			authHeader:    "Bearer abc123xyz",
			expectedKey:   "",
			expectedError: nil, // We'll check error message instead
			shouldError:   true,
		},
		{
			name:          "Malformed header - missing key",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: nil, // We'll check error message instead
			shouldError:   true,
		},
		{
			name:          "Malformed header - no space",
			authHeader:    "ApiKeyabc123",
			expectedKey:   "",
			expectedError: nil, // We'll check error message instead
			shouldError:   true,
		},
		{
			name:          "Empty API key",
			authHeader:    "ApiKey ",
			expectedKey:   "",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name:          "API key with single space",
			authHeader:    "ApiKey abc123xyz",
			expectedKey:   "abc123xyz",
			expectedError: nil,
			shouldError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create HTTP headers
			headers := make(http.Header)
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			// Call the function
			key, err := GetAPIKey(headers)

			// Check error expectations
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected an error but got none")
					return
				}
				
				// Check for specific error
				if tt.expectedError != nil && err != tt.expectedError {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
				
				// For malformed header errors, check the error message
				if tt.expectedError == nil && err.Error() != "malformed authorization header" {
					t.Errorf("Expected 'malformed authorization header' error, got %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
					return
				}
			}

			// Check key expectations (only if no error expected)
			if !tt.shouldError && key != tt.expectedKey {
				t.Errorf("Expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}

func TestGetAPIKey_CaseInsensitiveHeader(t *testing.T) {
	// Test that the function works with different cases of Authorization header
	testCases := []string{
		"authorization",
		"Authorization", 
		"AUTHORIZATION",
	}

	for _, headerName := range testCases {
		t.Run("Header case: "+headerName, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set(headerName, "ApiKey test123")

			key, err := GetAPIKey(headers)

			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if key != "test123" {
				t.Errorf("Expected key 'test123', got %q", key)
			}
		})
	}
}

func TestErrNoAuthHeaderIncluded(t *testing.T) {
	// Test that the exported error variable is properly defined
	if ErrNoAuthHeaderIncluded == nil {
		t.Error("ErrNoAuthHeaderIncluded should not be nil")
	}

	expectedMessage := "no authorization header included"
	if ErrNoAuthHeaderIncluded.Error() != expectedMessage {
		t.Errorf("Expected error message %q, got %q", expectedMessage, ErrNoAuthHeaderIncluded.Error())
	}
}