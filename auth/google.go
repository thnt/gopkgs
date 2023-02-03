package google

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	jwt.StandardClaims
	HD            string
	Email         string
	EmailVerified bool `json:"email_verified"`
	AZP           string
	Name          string
	Picture       string
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

type AuthClient interface {
	VerifyTokenID(string) (*Claims, error)
}

const (
	publicKeyURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type authClient struct {
	clientID           string
	publicKeys         map[string]*rsa.PublicKey
	fetchedPublicKeyTs time.Time
}

func NewAuthClient(clientID string) AuthClient {
	client := &authClient{
		clientID: clientID,
	}
	client.fetchPublicKeys()

	return client
}

func (c *authClient) fetchPublicKeys() error {
	res, err := http.DefaultClient.Get(publicKeyURL)
	if err != nil {
		return fmt.Errorf("failed send request: %v", err)
	}
	keys := map[string]string{}
	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	pkeys := map[string]*rsa.PublicKey{}
	for k, v := range keys {
		p, _ := pem.Decode([]byte(v))
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			continue
		}
		if p, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			pkeys[k] = p
		}
	}
	c.publicKeys = pkeys
	c.fetchedPublicKeyTs = time.Now()

	return nil
}

func (c *authClient) VerifyTokenID(tid string) (*Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tid, &claims, func(t *jwt.Token) (interface{}, error) {
		if kid, ok := t.Header["kid"].(string); ok {
			if k, ok := c.publicKeys[kid]; ok {
				return k, nil
			}
			if time.Since(c.fetchedPublicKeyTs).Minutes() > 10 {
				c.fetchPublicKeys()
			}
			if k, ok := c.publicKeys[kid]; ok {
				return k, nil
			}
		}
		return nil, fmt.Errorf("no public key found: kid=%v", t.Header["kid"])
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if claims.AZP != c.clientID {
		return nil, fmt.Errorf("client ID missmatch: %v", claims.AZP)
	}

	return &claims, nil
}
