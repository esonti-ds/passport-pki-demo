package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	s2sauthz "passport-pki-demo/internal/s2s-auth-authz"
)

// Simple helper to create a demo certificate with embedded user JWT
func createDemoCert() (*x509.Certificate, string, error) {
	// Create a demo healthcare user
	user := s2sauthz.User{
		ID:     "dr-demo-123",
		Email:  "dr.demo@hospital.com",
		Roles:  []string{"doctor", "patient-read", "patient-write", "media-read", "storage-read"},
		Tenant: "DemoHospital",
		Region: "US",
	}

	// Create user auth module and JWT
	userAuth, err := s2sauthz.NewPKIModule()
	if err != nil {
		return nil, "", err
	}

	userJWT, err := userAuth.CreateUserJWT(user)
	if err != nil {
		return nil, "", err
	}

	// Create a simple self-signed certificate with embedded user JWT
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	// Create custom extension with user JWT
	userJWTExtension := pkix.Extension{
		Id:       s2sauthz.UserJWTExtensionOID,
		Critical: false,
		Value:    []byte(userJWT),
	}

	template := x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "PatientService-Demo", Organization: []string{user.Tenant}},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{userJWTExtension},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, "", err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, "", err
	}

	return cert, userJWT, nil
}

// Decode and pretty print JWT
func decodeJWT(tokenString string) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid JWT format")
		return
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("Error decoding header: %v\n", err)
		return
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("Error decoding payload: %v\n", err)
		return
	}

	// Parse and pretty print
	var header, payload map[string]interface{}
	json.Unmarshal(headerBytes, &header)
	json.Unmarshal(payloadBytes, &payload)

	headerPretty, _ := json.MarshalIndent(header, "", "  ")
	payloadPretty, _ := json.MarshalIndent(payload, "", "  ")

	fmt.Printf("JWT Header:\n%s\n\n", headerPretty)
	fmt.Printf("JWT Payload:\n%s\n\n", payloadPretty)
}

func main() {
	fmt.Println("=== JWT Extractor Demo ===")
	fmt.Println("Demonstrating Service Passport creation and JWT extraction in healthcare service certificates")
	fmt.Println()

	// Create a demo certificate with embedded user JWT
	fmt.Println("1. Creating Demo Healthcare Service Passport with Embedded User JWT")
	cert, originalUserJWT, err := createDemoCert()
	if err != nil {
		fmt.Printf("Error creating demo cert: %v\n", err)
		return
	}
	fmt.Printf("   ✓ Service Certificate created with embedded User JWT (Service Passport)\n")
	fmt.Printf("   Service Name: %s\n", cert.Subject.CommonName)
	fmt.Printf("   Healthcare Organization: %v\n", cert.Subject.Organization)

	// Extract user JWT from certificate
	fmt.Println("\n2. Extracting User JWT from Service Passport")
	extractedUserJWT, err := s2sauthz.ExtractUserJWTFromServicePassport(cert)
	if err != nil {
		fmt.Printf("   ❌ Failed to extract user JWT: %v\n", err)
		return
	}
	fmt.Printf("   ✓ User JWT successfully extracted from Service Passport\n")
	fmt.Printf("   JWT Length: %d characters\n", len(extractedUserJWT))

	// Verify the extracted JWT matches the original
	fmt.Printf("   JWTs match: %v\n", extractedUserJWT == originalUserJWT)

	// Decode and display the user JWT contents
	fmt.Println("\n3. User JWT Contents")
	decodeJWT(extractedUserJWT)

	// Show certificate extensions
	fmt.Println("4. Certificate Extensions Analysis")
	fmt.Printf("   Total extensions: %d\n", len(cert.Extensions))
	for i, ext := range cert.Extensions {
		fmt.Printf("   Extension %d:\n", i+1)
		fmt.Printf("     OID: %s\n", ext.Id.String())
		fmt.Printf("     Critical: %v\n", ext.Critical)
		fmt.Printf("     Value length: %d bytes\n", len(ext.Value))

		if ext.Id.Equal(s2sauthz.UserJWTExtensionOID) {
			fmt.Printf("     ↳ This is the User JWT extension (creates Service Passport)!\n")
			fmt.Printf("     ↳ Contains: JWT token for S2S Authn + Authz\n")
		}
		fmt.Println()
	}

	fmt.Println("=== How Healthcare Services Would Use Service Passports ===")
	fmt.Println("1. Receive Service Passport JWT with x5c certificate chain from Prod Region service")
	fmt.Println("2. Validate certificate chain back to Prod Root")
	fmt.Println("3. Extract leaf certificate from x5c[0]")
	fmt.Println("4. Look for User JWT extension in leaf certificate")
	fmt.Println("5. Extract and validate the embedded user JWT")
	fmt.Println("6. Use healthcare user information for authorization decisions")
	fmt.Println()
	fmt.Println("🔐 This enables healthcare scenarios:")
	fmt.Println("   ✓ S2S Authn (Service Certificate)")
	fmt.Println("   ✓ S2S Authn + Authz (Service Passport with User JWT)")
	fmt.Println("   ✓ Fine-grained healthcare role-based access control")
	fmt.Println("   ✓ Cross-Prod Region medical data access")
	fmt.Println("   ✓ HIPAA-compliant user context preservation")
	fmt.Println("   ✓ Separate user auth module for healthcare compliance")
}
