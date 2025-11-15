package keycloak

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
)

type Client interface {
	ExchangeCode(code, redirectURI string) (*TokenResponse, error)
	VerifyToken(accessToken string) (*jwt.Token, error)
	RefreshToken(refreshToken string) (*TokenResponse, error)
	RevokeToken(refreshToken string) error
}

type client struct {
	baseURL      string
	clientID     string
	clientSecret string
	realm        string
	httpClient   *http.Client
}

func NewClient(baseURL, clientID, clientSecret, realm string, timeout time.Duration) Client {
	httpClient := http.Client{Timeout: timeout}
	return &client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		realm:        realm,
		httpClient:   &httpClient,
	}
}

func (c *client) ExchangeCode(code, redirectURI string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

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

	return &tokenResponse, nil
}

func (c *client) VerifyToken(accessToken string) (*jwt.Token, error) {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)

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

	return parsedToken, nil
}

func (c *client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

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

	return &tokenResponse, nil
}

func (c *client) RevokeToken(refreshToken string) error {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", c.baseURL, c.realm)

	data := url.Values{}
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("refresh_token", refreshToken)

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

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to logout, status: %d", resp.StatusCode)
	}

	return nil
}
