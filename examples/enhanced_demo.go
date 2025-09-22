package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"certificate-chain/userauth"

	"github.com/golang-jwt/jwt/v5"
)

// Helper functions from main.go (simplified for this demo)
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func createRootCA(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := generateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func createIntermediateCA(name string, parentCert *x509.Certificate, parentPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := generateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, priv.Public(), parentPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func createStorageCert(name string, interCert *x509.Certificate, interPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := generateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, interCert, priv.Public(), interPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func main() {
	fmt.Println("=== Enhanced PKI Demo: Account Certificates with Embedded User JWTs ===")
	fmt.Println()

	// Step 1: Initialize User Authentication Module
	fmt.Println("1. Initializing User Authentication Module")
	userAuthModule, err := userauth.NewUserAuthModule()
	if err != nil {
		fmt.Printf("Error creating user auth module: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   ✓ User authentication module ready")

	// Step 2: Create Sample Users
	fmt.Println("\n2. Creating Sample Users")
	alice := userauth.User{
		ID:     "alice-123",
		Email:  "alice@company.com",
		Roles:  []string{"admin", "storage-read", "storage-write"},
		Tenant: "CompanyA",
		Region: "US",
	}

	bob := userauth.User{
		ID:     "bob-456",
		Email:  "bob@company.com",
		Roles:  []string{"user", "storage-read"},
		Tenant: "CompanyB",
		Region: "Europe",
	}

	charlie := userauth.User{
		ID:     "charlie-789",
		Email:  "charlie@company.com",
		Roles:  []string{"guest"},
		Tenant: "CompanyC",
		Region: "Asia",
	}

	// Create user JWTs
	aliceUserJWT, err := userAuthModule.CreateUserJWT(alice)
	if err != nil {
		fmt.Printf("Error creating Alice's user JWT: %v\n", err)
		os.Exit(1)
	}

	bobUserJWT, err := userAuthModule.CreateUserJWT(bob)
	if err != nil {
		fmt.Printf("Error creating Bob's user JWT: %v\n", err)
		os.Exit(1)
	}

	charlieUserJWT, err := userAuthModule.CreateUserJWT(charlie)
	if err != nil {
		fmt.Printf("Error creating Charlie's user JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   ✓ Alice (admin, %s) - User JWT created\n", alice.Tenant)
	fmt.Printf("   ✓ Bob (user, %s) - User JWT created\n", bob.Tenant)
	fmt.Printf("   ✓ Charlie (guest, %s) - User JWT created\n", charlie.Tenant)

	// Step 3: Create PKI Infrastructure
	fmt.Println("\n3. Creating PKI Infrastructure")
	rootCert, rootPriv, err := createRootCA("Passport")
	if err != nil {
		fmt.Printf("Error creating root CA: %v\n", err)
		os.Exit(1)
	}

	// Regional intermediate CAs
	usRegion, usRegionPriv, err := createIntermediateCA("USRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating US region: %v\n", err)
		os.Exit(1)
	}

	europeRegion, europeRegionPriv, err := createIntermediateCA("EuropeRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Europe region: %v\n", err)
		os.Exit(1)
	}

	asiaRegion, asiaRegionPriv, err := createIntermediateCA("AsiaRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Asia region: %v\n", err)
		os.Exit(1)
	}

	globalRegion, globalRegionPriv, err := createIntermediateCA("GlobalRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Global region: %v\n", err)
		os.Exit(1)
	}

	// Storage certificate
	storageCert, _, err := createStorageCert("Storage", globalRegion, globalRegionPriv)
	if err != nil {
		fmt.Printf("Error creating storage cert: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("   ✓ PKI hierarchy created (Passport → Regional CAs → Storage)")

	// Step 4: Create Account Certificates with Embedded User JWTs
	fmt.Println("\n4. Creating Account Certificates with Embedded User JWTs")

	aliceAccountCert, aliceAccountPriv, err := userauth.CreateAccountCertWithUserJWT("Account-Alice", alice, aliceUserJWT, usRegion, usRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Alice's account cert: %v\n", err)
		os.Exit(1)
	}

	bobAccountCert, bobAccountPriv, err := userauth.CreateAccountCertWithUserJWT("Account-Bob", bob, bobUserJWT, europeRegion, europeRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Bob's account cert: %v\n", err)
		os.Exit(1)
	}

	charlieAccountCert, charlieAccountPriv, err := userauth.CreateAccountCertWithUserJWT("Account-Charlie", charlie, charlieUserJWT, asiaRegion, asiaRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Charlie's account cert: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("   ✓ Alice's Account certificate (US region) + embedded user JWT")
	fmt.Println("   ✓ Bob's Account certificate (Europe region) + embedded user JWT")
	fmt.Println("   ✓ Charlie's Account certificate (Asia region) + embedded user JWT")

	// Step 5: Test Access Scenarios
	fmt.Println("\n5. Testing Access Scenarios")

	// Test 1: Alice (admin) tries to read/write storage
	fmt.Println("\n   Test 1: Alice (Admin) - Read/Write Access")
	aliceClaims := jwt.MapClaims{
		"sub":    "alice-session",
		"scope":  "access_storage",
		"action": "write",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}

	aliceJWT, err := userauth.SignAccountJWTWithUser(aliceClaims, alice, aliceAccountPriv, aliceAccountCert, usRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Alice's JWT: %v\n", err)
	} else {
		// Storage validates the JWT and extracts user info
		accountToken, extractedUser, userJWT, err := userauth.ValidateAccountJWTAndExtractUser(aliceJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Access denied: %v\n", err)
		} else {
			fmt.Printf("      ✅ Account JWT validated successfully\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Roles: %v\n", extractedUser.Roles)

			// Check permissions
			canRead := userauth.AuthorizeUserAction(extractedUser, "storage-read")
			canWrite := userauth.AuthorizeUserAction(extractedUser, "storage-write")
			fmt.Printf("         Read permission: %v\n", canRead)
			fmt.Printf("         Write permission: %v\n", canWrite)

			// Verify we can access the raw user JWT too
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
			_ = accountToken
		}
	}

	// Test 2: Bob (user) tries to read storage
	fmt.Println("\n   Test 2: Bob (User) - Read Access")
	bobClaims := jwt.MapClaims{
		"sub":    "bob-session",
		"scope":  "access_storage",
		"action": "read",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}

	bobJWT, err := userauth.SignAccountJWTWithUser(bobClaims, bob, bobAccountPriv, bobAccountCert, europeRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Bob's JWT: %v\n", err)
	} else {
		accountToken, extractedUser, userJWT, err := userauth.ValidateAccountJWTAndExtractUser(bobJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Access denied: %v\n", err)
		} else {
			fmt.Printf("      ✅ Account JWT validated successfully\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Roles: %v\n", extractedUser.Roles)

			canRead := userauth.AuthorizeUserAction(extractedUser, "storage-read")
			canWrite := userauth.AuthorizeUserAction(extractedUser, "storage-write")
			fmt.Printf("         Read permission: %v\n", canRead)
			fmt.Printf("         Write permission: %v\n", canWrite)
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
			_ = accountToken
		}
	}

	// Test 3: Charlie (guest) tries to access storage
	fmt.Println("\n   Test 3: Charlie (Guest) - Storage Access")
	charlieClaims := jwt.MapClaims{
		"sub":    "charlie-session",
		"scope":  "access_storage",
		"action": "read",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}

	charlieJWT, err := userauth.SignAccountJWTWithUser(charlieClaims, charlie, charlieAccountPriv, charlieAccountCert, asiaRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Charlie's JWT: %v\n", err)
	} else {
		accountToken, extractedUser, userJWT, err := userauth.ValidateAccountJWTAndExtractUser(charlieJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Access denied: %v\n", err)
		} else {
			fmt.Printf("      ✅ Account JWT validated successfully\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Roles: %v\n", extractedUser.Roles)

			canRead := userauth.AuthorizeUserAction(extractedUser, "storage-read")
			canWrite := userauth.AuthorizeUserAction(extractedUser, "storage-write")
			fmt.Printf("         Read permission: %v\n", canRead)
			fmt.Printf("         Write permission: %v\n", canWrite)
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
			_ = accountToken
		}
	}

	fmt.Println("\n=== Architecture Summary ===")
	fmt.Println("🏗️ Two-Layer Security Architecture:")
	fmt.Println("   Layer 1: PKI Certificate Chain (Account Authentication)")
	fmt.Println("     - Validates Account certificate against Passport root CA")
	fmt.Println("     - Ensures regional authenticity")
	fmt.Println("     - Cryptographically verifies certificate chain")
	fmt.Println()
	fmt.Println("   Layer 2: Embedded User JWT (User Authorization)")
	fmt.Println("     - User JWT embedded in Account certificate extension")
	fmt.Println("     - Extracted and validated by separate auth module")
	fmt.Println("     - Fine-grained role-based access control")
	fmt.Println()
	fmt.Println("🔐 Benefits:")
	fmt.Println("   ✓ Account certificates prove regional/organizational identity")
	fmt.Println("   ✓ User JWTs provide individual user authorization")
	fmt.Println("   ✓ Storage can extract user context for policy decisions")
	fmt.Println("   ✓ Cross-region access with user-level permissions")
	fmt.Println("   ✓ Separation of concerns (PKI vs user auth)")
	fmt.Println("   ✓ Scalable across regions and tenants")

	// Prevent unused variable warnings
	_ = storageCert
}
