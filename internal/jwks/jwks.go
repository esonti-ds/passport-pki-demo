package jwks

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// CreateJWKS creates a JWKS JSON for a certificate with optional certificate chain
func CreateJWKS(cert *x509.Certificate, chain ...*x509.Certificate) ([]byte, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ECDSA public key")
	}

	kid := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))[:8] // Simple kid from cert hash

	x5c := []string{base64.StdEncoding.EncodeToString(cert.Raw)}
	for _, c := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}

	// Convert big.Int coordinates to fixed-size byte arrays for P-384
	xBytes := make([]byte, 48) // P-384 coordinate size
	yBytes := make([]byte, 48)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)

	jwk := JWK{
		Kty: "EC",
		Crv: "P-384",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Use: "sig",
		Kid: kid,
		X5c: x5c,
	}

	jwks := JWKS{Keys: []JWK{jwk}}
	return json.MarshalIndent(jwks, "", "  ")
}
