package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SignJWT signs a JWT with end-entity private key and includes x5c chain
func SignJWT(claims jwt.MapClaims, priv *ecdsa.PrivateKey, leafCert, interCert *x509.Certificate) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	// Include x5c: leaf first, then intermediate (root optional since trusted)
	x5c := []string{
		base64.StdEncoding.EncodeToString(leafCert.Raw),
		base64.StdEncoding.EncodeToString(interCert.Raw),
	}
	token.Header["x5c"] = x5c
	return token.SignedString(priv)
}

// ValidateJWT validates JWT using only root CA public key (via chain verification)
func ValidateJWT(signedToken string, rootCert *x509.Certificate) (*jwt.Token, error) {
	return jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		// Extract x5c from header
		x5cInterface, ok := token.Header["x5c"]
		if !ok {
			return nil, fmt.Errorf("missing x5c header")
		}
		x5cStrings, ok := x5cInterface.([]interface{})
		if !ok || len(x5cStrings) < 2 {
			return nil, fmt.Errorf("invalid x5c format")
		}

		// Decode base64 to DER bytes
		certs := make([]*x509.Certificate, len(x5cStrings))
		for i, s := range x5cStrings {
			str, ok := s.(string)
			if !ok {
				return nil, fmt.Errorf("x5c element not string")
			}
			der, err := base64.StdEncoding.DecodeString(str)
			if err != nil {
				return nil, err
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, err
			}
			certs[i] = cert
		}

		// certs[0] is leaf, certs[1] is intermediate
		leaf := certs[0]
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			intermediates.AddCert(certs[i])
		}

		roots := x509.NewCertPool()
		roots.AddCert(rootCert)

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}

		_, err := leaf.Verify(opts)
		if err != nil {
			return nil, fmt.Errorf("certificate chain validation failed: %v", err)
		}

		// Return the leaf public key for JWT signature verification
		return leaf.PublicKey, nil
	})
}
