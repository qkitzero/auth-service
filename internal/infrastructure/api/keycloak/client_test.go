package keycloak

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qkitzero/auth-service/internal/application/identity"
	"github.com/qkitzero/auth-service/internal/domain/token"
)

const (
	tokenPath  = "/realms/realm/protocol/openid-connect/token"
	certsPath  = "/realms/realm/protocol/openid-connect/certs"
	logoutPath = "/realms/realm/protocol/openid-connect/logout"
)

const invalidBaseURL = "http://\x7f"

var (
	errUnmapped     = errors.New("unmapped error")
	errRequestBuild = errors.New("request build error")
)

func assertError(t *testing.T, err error, want ...error) {
	t.Helper()

	if len(want) == 0 {
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
		return
	}
	if err == nil {
		t.Errorf("expected error %v, but got nil", want)
		return
	}
	for _, wantErr := range want {
		switch wantErr {
		case errUnmapped:
			if errors.Is(err, token.ErrInvalidGrant) || errors.Is(err, token.ErrInvalidToken) {
				t.Errorf("expected an unmapped error, but got %v", err)
			}
		case errRequestBuild:
			var urlErr *url.Error
			if !errors.As(err, &urlErr) || urlErr.Op != "parse" {
				t.Errorf("expected a request build error, but got %v", err)
			}
		default:
			if !errors.Is(err, wantErr) {
				t.Errorf("expected errors.Is(err, %v), but got %v", wantErr, err)
			}
		}
	}
}

func newPublicKey(kid string, key *rsa.PublicKey) PublicKey {
	return PublicKey{
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func jwksHandler(keys ...PublicKey) http.HandlerFunc {
	if keys == nil {
		keys = []PublicKey{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PublicKeyResponse{Keys: keys})
	}
}

func statusHandler(statusCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
	}
}

func tokenResponseHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&TokenResponse{
			AccessToken:      "accessToken",
			RefreshToken:     "refreshToken",
			ExpiresIn:        3600,
			RefreshExpiresIn: 3600,
		})
	}
}

func slowHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		handler(w, r)
	}
}

func expectRequest(t *testing.T, wantMethod, wantPath string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %s, want %s", r.Method, wantMethod)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		handler(w, r)
	}
}

func newTestClient(baseURL, serverURL string) identity.Provider {
	if baseURL == "" {
		baseURL = serverURL
	}
	return NewClient(baseURL, "clientID", "clientSecret", "realm", 1*time.Second)
}

func TestLogin(t *testing.T) {
	t.Parallel()

	client := NewClient("https://keycloak.example.com", "clientID", "clientSecret", "realm", 1*time.Second)

	loginURL, err := client.Login(context.Background(), "http://localhost:3000/callback")
	assertError(t, err, errUnmapped, errNotImplemented)

	if loginURL != "" {
		t.Errorf("expected empty login URL, but got %s", loginURL)
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		code        string
		redirectURI string
		baseURL     string
		handler     http.HandlerFunc
		wantErrs    []error
		expected    *identity.TokenResult
	}{
		{
			name:        "success exchange code",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler:     tokenResponseHandler(),
			wantErrs:    nil,
			expected: &identity.TokenResult{
				AccessToken:  "accessToken",
				RefreshToken: "refreshToken",
			},
		},
		{
			name:        "failure invalid grant on bad request",
			code:        "expiredCode",
			redirectURI: "http://localhost:3000/callback",
			handler:     statusHandler(http.StatusBadRequest),
			wantErrs:    []error{token.ErrInvalidGrant},
			expected:    nil,
		},
		{
			name:        "failure invalid grant on unauthorized",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler:     statusHandler(http.StatusUnauthorized),
			wantErrs:    []error{token.ErrInvalidGrant},
			expected:    nil,
		},
		{
			name:        "failure keycloak error",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler:     statusHandler(http.StatusInternalServerError),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
		{
			name:        "failure keycloak json error",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler:     statusHandler(http.StatusOK),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
		{
			name:        "failure invalid base url",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			baseURL:     invalidBaseURL,
			handler:     tokenResponseHandler(),
			wantErrs:    []error{errUnmapped, errRequestBuild},
			expected:    nil,
		},
		{
			name:        "failure timeout",
			code:        "code",
			redirectURI: "http://localhost:3000/callback",
			handler:     slowHandler(tokenResponseHandler()),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(expectRequest(t, http.MethodPost, tokenPath, tt.handler))
			defer server.Close()

			client := newTestClient(tt.baseURL, server.URL)

			result, err := client.ExchangeCode(context.Background(), tt.code, tt.redirectURI)
			assertError(t, err, tt.wantErrs...)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("token = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	kid := "kid"
	subject := "126ff835-d63f-4f44-a3aa-b5e530b98991"

	signToken := func(method jwt.SigningMethod, key any, headerKid string, claims jwt.MapClaims) string {
		t.Helper()

		jwtToken := jwt.NewWithClaims(method, claims)
		if headerKid != "" {
			jwtToken.Header["kid"] = headerKid
		}
		signed, signErr := jwtToken.SignedString(key)
		if signErr != nil {
			t.Fatalf("failed to sign token: %v", signErr)
		}
		return signed
	}

	accessToken := signToken(jwt.SigningMethodRS256, privateKey, kid, jwt.MapClaims{"sub": subject})

	t.Parallel()
	tests := []struct {
		name        string
		accessToken string
		baseURL     string
		handler     http.HandlerFunc
		wantErrs    []error
		expected    *identity.VerifyResult
	}{
		{
			name:        "success verify token",
			accessToken: accessToken,
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    nil,
			expected:    &identity.VerifyResult{Subject: subject},
		},
		{
			name:        "failure invalid token",
			accessToken: "invalidToken",
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    []error{token.ErrInvalidToken, jwt.ErrTokenMalformed},
			expected:    nil,
		},
		{
			name:        "failure unexpected signing method",
			accessToken: signToken(jwt.SigningMethodHS256, []byte("secret"), kid, jwt.MapClaims{"sub": subject}),
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    []error{token.ErrInvalidToken, errUnexpectedSigningMethod},
			expected:    nil,
		},
		{
			name:        "failure no kid in token header",
			accessToken: signToken(jwt.SigningMethodRS256, privateKey, "", jwt.MapClaims{"sub": subject}),
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    []error{token.ErrInvalidToken, errMissingKid},
			expected:    nil,
		},
		{
			name:        "failure could not find public key",
			accessToken: accessToken,
			handler:     jwksHandler(newPublicKey("otherKid", publicKey)),
			wantErrs:    []error{token.ErrInvalidToken, errPublicKeyNotFound},
			expected:    nil,
		},
		{
			name:        "failure invalid public key modulus",
			accessToken: accessToken,
			handler: jwksHandler(PublicKey{
				Kid: kid,
				N:   "not!base64",
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			}),
			wantErrs: []error{errUnmapped, errInvalidPublicKeyModulus},
			expected: nil,
		},
		{
			name:        "failure invalid public key exponent",
			accessToken: accessToken,
			handler: jwksHandler(PublicKey{
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				E:   "not!base64",
			}),
			wantErrs: []error{errUnmapped, errInvalidPublicKeyExponent},
			expected: nil,
		},
		{
			name:        "failure subject is not a string",
			accessToken: signToken(jwt.SigningMethodRS256, privateKey, kid, jwt.MapClaims{"sub": 123}),
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    []error{token.ErrInvalidToken, jwt.ErrInvalidType},
			expected:    nil,
		},
		{
			name:        "failure keycloak error",
			accessToken: accessToken,
			handler:     statusHandler(http.StatusInternalServerError),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
		{
			name:        "failure keycloak json error",
			accessToken: accessToken,
			handler:     statusHandler(http.StatusOK),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
		{
			name:        "failure keycloak response has no keys",
			accessToken: accessToken,
			handler:     jwksHandler(),
			wantErrs:    []error{errUnmapped, errMissingPublicKey},
			expected:    nil,
		},
		{
			name:        "failure invalid base url",
			accessToken: accessToken,
			baseURL:     invalidBaseURL,
			handler:     jwksHandler(newPublicKey(kid, publicKey)),
			wantErrs:    []error{errUnmapped, errRequestBuild},
			expected:    nil,
		},
		{
			name:        "failure timeout",
			accessToken: accessToken,
			handler:     slowHandler(jwksHandler(newPublicKey(kid, publicKey))),
			wantErrs:    []error{errUnmapped},
			expected:    nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(expectRequest(t, http.MethodGet, certsPath, tt.handler))
			defer server.Close()

			client := newTestClient(tt.baseURL, server.URL)

			result, err := client.VerifyToken(context.Background(), tt.accessToken)
			assertError(t, err, tt.wantErrs...)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("result = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		refreshToken string
		baseURL      string
		handler      http.HandlerFunc
		wantErrs     []error
		expected     *identity.TokenResult
	}{
		{
			name:         "success refresh token",
			refreshToken: "refreshToken",
			handler:      tokenResponseHandler(),
			wantErrs:     nil,
			expected: &identity.TokenResult{
				AccessToken:  "accessToken",
				RefreshToken: "refreshToken",
			},
		},
		{
			name:         "failure invalid grant on bad request",
			refreshToken: "expiredRefreshToken",
			handler:      statusHandler(http.StatusBadRequest),
			wantErrs:     []error{token.ErrInvalidGrant},
			expected:     nil,
		},
		{
			name:         "failure invalid grant on unauthorized",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusUnauthorized),
			wantErrs:     []error{token.ErrInvalidGrant},
			expected:     nil,
		},
		{
			name:         "failure keycloak error",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusInternalServerError),
			wantErrs:     []error{errUnmapped},
			expected:     nil,
		},
		{
			name:         "failure keycloak json error",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusOK),
			wantErrs:     []error{errUnmapped},
			expected:     nil,
		},
		{
			name:         "failure invalid base url",
			refreshToken: "refreshToken",
			baseURL:      invalidBaseURL,
			handler:      tokenResponseHandler(),
			wantErrs:     []error{errUnmapped, errRequestBuild},
			expected:     nil,
		},
		{
			name:         "failure timeout",
			refreshToken: "refreshToken",
			handler:      slowHandler(tokenResponseHandler()),
			wantErrs:     []error{errUnmapped},
			expected:     nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(expectRequest(t, http.MethodPost, tokenPath, tt.handler))
			defer server.Close()

			client := newTestClient(tt.baseURL, server.URL)

			result, err := client.RefreshToken(context.Background(), tt.refreshToken)
			assertError(t, err, tt.wantErrs...)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("token = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		refreshToken string
		baseURL      string
		handler      http.HandlerFunc
		wantErrs     []error
	}{
		{
			name:         "success revoke token",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusNoContent),
			wantErrs:     nil,
		},
		{
			name:         "failure invalid grant on bad request",
			refreshToken: "expiredRefreshToken",
			handler:      statusHandler(http.StatusBadRequest),
			wantErrs:     []error{token.ErrInvalidGrant},
		},
		{
			name:         "failure invalid grant on unauthorized",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusUnauthorized),
			wantErrs:     []error{token.ErrInvalidGrant},
		},
		{
			name:         "failure unexpected success status",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusOK),
			wantErrs:     []error{errUnmapped},
		},
		{
			name:         "failure keycloak error",
			refreshToken: "refreshToken",
			handler:      statusHandler(http.StatusInternalServerError),
			wantErrs:     []error{errUnmapped},
		},
		{
			name:         "failure invalid base url",
			refreshToken: "refreshToken",
			baseURL:      invalidBaseURL,
			handler:      statusHandler(http.StatusNoContent),
			wantErrs:     []error{errUnmapped, errRequestBuild},
		},
		{
			name:         "failure timeout",
			refreshToken: "refreshToken",
			handler:      slowHandler(statusHandler(http.StatusNoContent)),
			wantErrs:     []error{errUnmapped},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(expectRequest(t, http.MethodPost, logoutPath, tt.handler))
			defer server.Close()

			client := newTestClient(tt.baseURL, server.URL)

			assertError(t, client.RevokeToken(context.Background(), tt.refreshToken), tt.wantErrs...)
		})
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()

	client := NewClient("https://keycloak.example.com", "clientID", "clientSecret", "realm", 1*time.Second)

	logoutURL, err := client.Logout(context.Background(), "http://localhost:3000")
	assertError(t, err, errUnmapped, errNotImplemented)

	if logoutURL != "" {
		t.Errorf("expected empty logout URL, but got %s", logoutURL)
	}
}

func TestGetM2MToken(t *testing.T) {
	t.Parallel()

	client := NewClient("https://keycloak.example.com", "clientID", "clientSecret", "realm", 1*time.Second)

	result, err := client.GetM2MToken(context.Background(), "m2mClientID", "m2mClientSecret")
	assertError(t, err, errUnmapped, errNotImplemented)

	if result != nil {
		t.Errorf("expected nil token, but got %v", result)
	}
}

func TestContextCancellation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		invoke func(context.Context, identity.Provider) error
	}{
		{
			name: "exchange code",
			invoke: func(ctx context.Context, client identity.Provider) error {
				_, err := client.ExchangeCode(ctx, "code", "http://localhost:3000/callback")
				return err
			},
		},
		{
			name: "verify token",
			invoke: func(ctx context.Context, client identity.Provider) error {
				_, err := client.VerifyToken(ctx, "accessToken")
				return err
			},
		},
		{
			name: "refresh token",
			invoke: func(ctx context.Context, client identity.Provider) error {
				_, err := client.RefreshToken(ctx, "refreshToken")
				return err
			},
		},
		{
			name: "revoke token",
			invoke: func(ctx context.Context, client identity.Provider) error {
				return client.RevokeToken(ctx, "refreshToken")
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(statusHandler(http.StatusOK))
			defer server.Close()

			client := NewClient(server.URL, "clientID", "clientSecret", "realm", 30*time.Second)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			if err := tt.invoke(ctx, client); !errors.Is(err, context.Canceled) {
				t.Errorf("expected errors.Is(err, context.Canceled), but got %v", err)
			}
		})
	}
}
