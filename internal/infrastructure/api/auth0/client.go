package auth0

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qkitzero/auth-service/internal/application/identity"
)

type client struct {
	baseURL      string
	clientID     string
	clientSecret string
	audience     string
	httpClient   *http.Client
}

func NewClient(baseURL, clientID, clientSecret, audience string, timeout time.Duration) identity.Provider {
	httpClient := http.Client{Timeout: timeout}
	return &client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		audience:     audience,
		httpClient:   &httpClient,
	}
}

func (c *client) Login(redirectURI string) (string, error) {
	endpoint := fmt.Sprintf("%s/authorize", c.baseURL)

	params := url.Values{}
	params.Set("client_id", c.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("audience", c.audience)
	params.Set("scope", "openid profile email offline_access")

	loginURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())

	return loginURL, nil
}

func (c *client) ExchangeCode(code, redirectURI string) (*identity.TokenResult, error) {
	endpoint := fmt.Sprintf("%s/oauth/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange code, status: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &identity.TokenResult{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
	}, nil
}

func (c *client) VerifyToken(accessToken string) (*identity.VerifyResult, error) {
	endpoint := fmt.Sprintf("%s/.well-known/jwks.json", c.baseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange code, status: %d", resp.StatusCode)
	}

	var publicKeyResponse PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&publicKeyResponse); err != nil {
		return nil, err
	}

	if len(publicKeyResponse.Keys) == 0 {
		return nil, fmt.Errorf("missing public key")
	}

	parsedToken, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid := token.Header["kid"]
		if kid == nil {
			return nil, fmt.Errorf("no kid in token header")
		}

		var publicKey *PublicKey

		for _, key := range publicKeyResponse.Keys {
			if key.Kid == kid {
				publicKey = &key
				break
			}
		}

		if publicKey == nil {
			return nil, fmt.Errorf("could not find public key")
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(publicKey.N)
		if err != nil {
			return nil, err
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(publicKey.E)
		if err != nil {
			return nil, err
		}

		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())

		return &rsa.PublicKey{N: n, E: e}, nil
	})
	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	subject, err := parsedToken.Claims.GetSubject()
	if err != nil {
		return nil, err
	}

	return &identity.VerifyResult{Subject: subject}, nil
}

func (c *client) RefreshToken(refreshToken string) (*identity.TokenResult, error) {
	endpoint := fmt.Sprintf("%s/oauth/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange code, status: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &identity.TokenResult{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
	}, nil
}

func (c *client) RevokeToken(refreshToken string) error {
	endpoint := fmt.Sprintf("%s/oauth/revoke", c.baseURL)

	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("token", refreshToken)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to logout, status: %d", resp.StatusCode)
	}

	return nil
}

func (c *client) Logout(returnTo string) (string, error) {
	endpoint := fmt.Sprintf("%s/v2/logout", c.baseURL)

	params := url.Values{}
	params.Set("client_id", c.clientID)
	params.Set("returnTo", returnTo)

	logoutURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())

	return logoutURL, nil
}

func (c *client) GetM2MToken(clientID, clientSecret string) (*identity.TokenResult, error) {
	endpoint := fmt.Sprintf("%s/oauth/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("audience", c.audience)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get m2m token, status: %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &identity.TokenResult{
		AccessToken: tokenResponse.AccessToken,
	}, nil
}
