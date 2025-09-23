package s2sauthauthorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Custom OID for embedding user JWT in certificate extensions
var UserJWTExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 999, 1, 1} // Private enterprise OID

// User represents a user that will be embedded in the Service Passport
type User struct {
	ID     string   `json:"id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	Tenant string   `json:"tenant"`
	Region string   `json:"region"`
}

// UserAuthModule handles user JWT creation and validation for S2S Authentication + Authorization
type UserAuthModule struct {
	userSigningKey *ecdsa.PrivateKey
	userPublicKey  *ecdsa.PublicKey
}

// NewUserAuthModule creates a new user authentication module for S2S Auth + Authz
func NewUserAuthModule() (*UserAuthModule, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &UserAuthModule{
		userSigningKey: key,
		userPublicKey:  &key.PublicKey,
	}, nil
}

// CreateUserJWT creates a JWT for a specific user
func (uam *UserAuthModule) CreateUserJWT(user User) (string, error) {
	claims := jwt.MapClaims{
		"sub":    user.ID,
		"email":  user.Email,
		"roles":  user.Roles,
		"tenant": user.Tenant,
		"region": user.Region,
		"iss":    "UserAuthService",
		"aud":    "Storage",
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  "user_authorization",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(uam.userSigningKey)
}

// ValidateUserJWT validates an extracted user JWT
func (uam *UserAuthModule) ValidateUserJWT(tokenString string) (*jwt.Token, *User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return uam.userPublicKey, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("user JWT validation failed: %v", err)
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("user JWT is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid claims format")
	}

	// Extract user information
	user := &User{
		ID:     getStringClaim(claims, "sub"),
		Email:  getStringClaim(claims, "email"),
		Tenant: getStringClaim(claims, "tenant"),
		Region: getStringClaim(claims, "region"),
	}

	// Extract roles array
	if rolesInterface, ok := claims["roles"].([]interface{}); ok {
		for _, role := range rolesInterface {
			if roleStr, ok := role.(string); ok {
				user.Roles = append(user.Roles, roleStr)
			}
		}
	}

	return token, user, nil
}

// Helper function to get string claims
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

// CreateServicePassport creates a Service Passport (Service Certificate with embedded user JWT for S2S Authentication + Authorization)
func CreateServicePassport(serviceName string, user User, userJWT string, prodRegionCert *x509.Certificate, prodRegionPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create custom extension with user JWT (this enables S2S Authentication + Authorization)
	userJWTExtension := pkix.Extension{
		Id:       UserJWTExtensionOID,
		Critical: false,
		Value:    []byte(userJWT),
	}

	template := x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: serviceName, Organization: []string{user.Tenant}},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{userJWTExtension},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, prodRegionCert, priv.Public(), prodRegionPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// ExtractUserJWTFromServicePassport extracts the user JWT from a Service Passport's certificate extensions
func ExtractUserJWTFromServicePassport(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(UserJWTExtensionOID) {
			return string(ext.Value), nil
		}
	}
	return "", fmt.Errorf("no user JWT found in Service Passport certificate")
}

// CreateServicePassportJWT creates a Service Passport JWT with embedded user context (enables S2S Authentication + Authorization)
func CreateServicePassportJWT(claims jwt.MapClaims, user User, priv *ecdsa.PrivateKey, leafCert, prodRegionCert *x509.Certificate) (string, error) {
	// Add user context to the Service Passport JWT claims
	claims["user_id"] = user.ID
	claims["user_email"] = user.Email
	claims["user_tenant"] = user.Tenant
	claims["has_embedded_user_auth"] = true
	claims["passport_type"] = "service_with_user_context"
	claims["auth_type"] = "s2s_authentication_authorization" // Service-to-Service Authentication + Authorization

	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	x5c := []string{
		base64.StdEncoding.EncodeToString(leafCert.Raw),
		base64.StdEncoding.EncodeToString(prodRegionCert.Raw),
	}
	token.Header["x5c"] = x5c
	return token.SignedString(priv)
}

// ValidateServicePassportAndExtractUser validates a Service Passport (Service Certificate with embedded User JWT for S2S Authentication + Authorization) and extracts user context
func ValidateServicePassportAndExtractUser(signedToken string, prodRootCert *x509.Certificate, userAuth *UserAuthModule) (*jwt.Token, *User, string, error) {
	var extractedUserJWT string
	var extractedUser *User

	// Parse and validate the Service Passport JWT
	servicePassportToken, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		// Extract and validate certificate chain from x5c header
		x5cInterface, ok := token.Header["x5c"]
		if !ok {
			return nil, fmt.Errorf("missing x5c header in service passport")
		}
		x5cStrings, ok := x5cInterface.([]interface{})
		if !ok || len(x5cStrings) < 2 {
			return nil, fmt.Errorf("invalid x5c format in service passport")
		}

		// Decode service certificates from x5c
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

		// Build service certificate chain and verify against Prod Root
		leaf := certs[0]
		prodRegionCerts := x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			prodRegionCerts.AddCert(certs[i])
		}

		prodRoots := x509.NewCertPool()
		prodRoots.AddCert(prodRootCert)

		opts := x509.VerifyOptions{
			Roots:         prodRoots,
			Intermediates: prodRegionCerts,
		}

		_, err := leaf.Verify(opts)
		if err != nil {
			return nil, fmt.Errorf("service certificate chain validation failed against Prod Root: %v", err)
		}

		// Extract user JWT from Service Passport certificate extension (enables S2S Authentication + Authorization)
		userJWT, err := ExtractUserJWTFromServicePassport(leaf)
		if err != nil {
			return nil, fmt.Errorf("failed to extract user JWT from Service Passport certificate: %v", err)
		}

		// Validate extracted user JWT
		_, user, err := userAuth.ValidateUserJWT(userJWT)
		if err != nil {
			return nil, fmt.Errorf("user JWT validation failed: %v", err)
		}

		// Store for later retrieval
		extractedUserJWT = userJWT
		extractedUser = user

		return leaf.PublicKey, nil
	})

	if err != nil {
		return nil, nil, "", err
	}

	return servicePassportToken, extractedUser, extractedUserJWT, nil
}

// AuthorizeUserAction checks if a user has permission for a specific action
func AuthorizeUserAction(user *User, action string) bool {
	switch action {
	case "storage-read":
		for _, role := range user.Roles {
			if role == "storage-read" || role == "storage-write" || role == "admin" || role == "doctor" {
				return true
			}
		}
	case "storage-write":
		for _, role := range user.Roles {
			if role == "storage-write" || role == "admin" || role == "doctor" {
				return true
			}
		}
	case "patient-read":
		for _, role := range user.Roles {
			if role == "patient-read" || role == "patient-write" || role == "doctor" || role == "nurse" || role == "admin" {
				return true
			}
		}
	case "patient-write":
		for _, role := range user.Roles {
			if role == "patient-write" || role == "doctor" || role == "admin" {
				return true
			}
		}
	case "media-read":
		for _, role := range user.Roles {
			if role == "media-read" || role == "media-write" || role == "doctor" || role == "nurse" || role == "patient" || role == "admin" {
				return true
			}
		}
	case "media-write":
		for _, role := range user.Roles {
			if role == "media-write" || role == "doctor" || role == "admin" {
				return true
			}
		}
	case "admin":
		for _, role := range user.Roles {
			if role == "admin" || role == "doctor" {
				return true
			}
		}
	}
	return false
}
