package keycloak

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		success       bool
		code          string
		redirectURI   string
		handler       http.HandlerFunc
		expectedToken *TokenResponse
	}{
		{
			name:        "success exchange code",
			success:     true,
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&TokenResponse{
					AccessToken:      "accessToken",
					RefreshToken:     "refreshToken",
					ExpiresIn:        3600,
					RefreshExpiresIn: 3600,
				})
			},
			expectedToken: &TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			},
		},
		{
			name:        "failure keycloak error",
			success:     false,
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedToken: nil,
		},
		{
			name:        "failure keycloak json error",
			success:     false,
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedToken: nil,
		},
		{
			name:        "failure timeout",
			success:     false,
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
			expectedToken: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(server.URL, "clientID", "clientSecret", "realm")

			token, err := client.ExchangeCode(tt.code, tt.redirectURI)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}

			if tt.success && !reflect.DeepEqual(token, tt.expectedToken) {
				t.Errorf("expected token %+v, got %+v", tt.expectedToken, token)
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	kid := "kid"

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "sub"})
	token.Header["kid"] = kid
	accessToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Errorf("failed to sign token: %v", err)
	}

	t.Parallel()
	tests := []struct {
		name        string
		success     bool
		accessToken string
		handler     http.HandlerFunc
	}{
		{
			name:        "success verify token",
			success:     true,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{
					Keys: []PublicKey{
						{
							Kid: kid,
							N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
							E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
						},
					},
				})
			},
		},
		{
			name:        "failure invalid token",
			success:     false,
			accessToken: "invalidToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{
					Keys: []PublicKey{
						{
							Kid: kid,
							N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
							E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
						},
					},
				})
			},
		},
		{
			name:    "failure unexpected signing method",
			success: false,
			accessToken: func() string {
				unexpectedSigningMethodToken, err := jwt.New(jwt.SigningMethodHS256).SignedString([]byte("secret"))
				if err != nil {
					t.Errorf("failed to sign token: %v", err)
				}
				return unexpectedSigningMethodToken
			}(),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{
					Keys: []PublicKey{
						{
							Kid: kid,
							N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
							E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
						},
					},
				})
			},
		},
		{
			name:    "failure no kid in token header",
			success: false,
			accessToken: func() string {
				tokenWithoutKid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "sub"})
				accessToken, err := tokenWithoutKid.SignedString(privateKey)
				if err != nil {
					t.Errorf("failed to sign token: %v", err)
				}
				return accessToken
			}(),
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{
					Keys: []PublicKey{
						{
							Kid: kid,
							N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
							E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
						},
					},
				})
			},
		},
		{
			name:        "failure keycloak error",
			success:     false,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name:        "failure keycloak json error",
			success:     false,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name:        "failure keycloak response has no keys",
			success:     false,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{Keys: []PublicKey{}})
			},
		},
		{
			name:        "failure could not find public key",
			success:     false,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(PublicKeyResponse{
					Keys: []PublicKey{
						{
							Kid: "",
							N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
							E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
						},
					},
				})
			},
		},
		{
			name:        "failure timeout",
			success:     false,
			accessToken: accessToken,
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(server.URL, "clientID", "clientSecret", "realm")

			_, err := client.VerifyToken(tt.accessToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		success       bool
		refreshToken  string
		handler       http.HandlerFunc
		expectedToken *TokenResponse
	}{
		{
			name:         "success refresh token",
			success:      true,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&TokenResponse{
					AccessToken:      "accessToken",
					RefreshToken:     "refreshToken",
					ExpiresIn:        3600,
					RefreshExpiresIn: 3600,
				})
			},
			expectedToken: &TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			},
		},
		{
			name:         "failure keycloak error",
			success:      false,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedToken: nil,
		},
		{
			name:         "failure keycloak json error",
			success:      false,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedToken: nil,
		},
		{
			name:         "failure timeout",
			success:      false,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
			expectedToken: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(server.URL, "clientID", "clientSecret", "realm")

			token, err := client.RefreshToken(tt.refreshToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}

			if tt.success && !reflect.DeepEqual(token, tt.expectedToken) {
				t.Errorf("expected token %+v, got %+v", tt.expectedToken, token)
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		success      bool
		refreshToken string
		handler      http.HandlerFunc
	}{
		{
			name:         "success revoke token",
			success:      true,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		},
		{
			name:         "failure keycloak error",
			success:      false,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name:         "failure timeout",
			success:      false,
			refreshToken: "refreshToken",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Second)
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClient(server.URL, "clientID", "clientSecret", "realm")

			err := client.RevokeToken(tt.refreshToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}
