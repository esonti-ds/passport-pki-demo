package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"passport-pki-demo/internal/jwks"
	"passport-pki-demo/internal/pki"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	fmt.Println("=== Basic PKI Certificate Chain Demo ===")
	fmt.Println()

	// Create Root CA: Passport
	fmt.Println("1. Creating Root CA: Passport")
	rootCert, rootPriv, err := pki.CreateRootCA("Passport")
	if err != nil {
		fmt.Printf("Error creating root CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Root CA 'Passport' created successfully\n")

	// Create Intermediate CAs
	fmt.Println("\n2. Creating Intermediate CAs")
	globalCert, globalPriv, err := pki.CreateIntermediateCA("GlobalRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating GlobalRegion: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ GlobalRegion CA created\n")

	usCert, usPriv, err := pki.CreateIntermediateCA("USRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating USRegion: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ USRegion CA created\n")

	europeCert, europePriv, err := pki.CreateIntermediateCA("EuropeRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating EuropeRegion: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ EuropeRegion CA created\n")

	asiaCert, asiaPriv, err := pki.CreateIntermediateCA("AsiaRegion", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating AsiaRegion: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ AsiaRegion CA created\n")

	// Create Storage cert signed by GlobalRegion
	fmt.Println("\n3. Creating End-Entity Certificates")
	storageCert, storagePriv, err := pki.CreateEndEntityCert("Storage", globalCert, globalPriv)
	if err != nil {
		fmt.Printf("Error creating Storage cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Storage cert (signed by GlobalRegion) created\n")

	// Create Account certs signed by regional intermediates
	accountUSCert, accountUSPriv, err := pki.CreateEndEntityCert("Account-US", usCert, usPriv)
	if err != nil {
		fmt.Printf("Error creating Account-US cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Account-US cert (signed by USRegion) created\n")

	accountEuropeCert, accountEuropePriv, err := pki.CreateEndEntityCert("Account-Europe", europeCert, europePriv)
	if err != nil {
		fmt.Printf("Error creating Account-Europe cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Account-Europe cert (signed by EuropeRegion) created\n")

	accountAsiaCert, accountAsiaPriv, err := pki.CreateEndEntityCert("Account-Asia", asiaCert, asiaPriv)
	if err != nil {
		fmt.Printf("Error creating Account-Asia cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Account-Asia cert (signed by AsiaRegion) created\n")

	// Demo: Account from US region trying to access Storage
	fmt.Println("\n4. Testing Cross-Region Access")
	testRegions := []struct {
		name        string
		accountCert *x509.Certificate
		accountPriv *ecdsa.PrivateKey
		regionCert  *x509.Certificate
		region      string
	}{
		{"US Account", accountUSCert, accountUSPriv, usCert, "US"},
		{"Europe Account", accountEuropeCert, accountEuropePriv, europeCert, "Europe"},
		{"Asia Account", accountAsiaCert, accountAsiaPriv, asiaCert, "Asia"},
	}

	for _, test := range testRegions {
		fmt.Printf("\n   Testing: %s → Storage\n", test.name)
		claims := jwt.MapClaims{
			"sub":    fmt.Sprintf("account-%s", test.region),
			"scope":  "access_storage",
			"region": test.region,
			"exp":    time.Now().Add(time.Hour).Unix(),
			"iat":    time.Now().Unix(),
		}

		jwtToken, err := pki.SignJWT(claims, test.accountPriv, test.accountCert, test.regionCert)
		if err != nil {
			fmt.Printf("      ❌ Error signing JWT: %v\n", err)
			continue
		}
		fmt.Printf("      ✓ JWT signed successfully\n")

		// Validate the JWT at Storage using only the root CA (Passport)
		parsedToken, err := pki.ValidateJWT(jwtToken, rootCert)
		if err != nil {
			fmt.Printf("      ❌ JWT validation failed: %v\n", err)
			continue
		}
		fmt.Printf("      ✓ JWT validated! Certificate chain verified through Passport root CA\n")
		fmt.Printf("      Claims: %v\n", parsedToken.Claims)
	}

	// Generate JWKS for different components
	fmt.Println("\n5. Generating JWKS (JSON Web Key Sets)")

	// Root CA JWKS
	rootJWKS, err := jwks.CreateJWKS(rootCert)
	if err != nil {
		fmt.Printf("Error creating root JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Root CA (Passport) JWKS created\n")

	// GlobalRegion JWKS with certificate chain
	globalJWKS, err := jwks.CreateJWKS(globalCert, rootCert)
	if err != nil {
		fmt.Printf("Error creating GlobalRegion JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ GlobalRegion JWKS created (with certificate chain)\n")

	// Storage service JWKS
	storageJWKS, err := jwks.CreateJWKS(storageCert, globalCert, rootCert)
	if err != nil {
		fmt.Printf("Error creating Storage JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Storage service JWKS created (with full certificate chain)\n")

	fmt.Println("\n=== Summary ===")
	fmt.Println("Certificate Hierarchy:")
	fmt.Println("  Passport (Root CA)")
	fmt.Println("  ├── GlobalRegion (Intermediate CA)")
	fmt.Println("  │   └── Storage (End Entity)")
	fmt.Println("  ├── USRegion (Intermediate CA)")
	fmt.Println("  │   └── Account-US (End Entity)")
	fmt.Println("  ├── EuropeRegion (Intermediate CA)")
	fmt.Println("  │   └── Account-Europe (End Entity)")
	fmt.Println("  └── AsiaRegion (Intermediate CA)")
	fmt.Println("      └── Account-Asia (End Entity)")
	fmt.Println()
	fmt.Println("✅ All regional accounts can access Storage because:")
	fmt.Println("   - Each account signs JWTs with their regional certificate")
	fmt.Println("   - JWTs include x5c header with certificate chain")
	fmt.Println("   - Storage validates chains back to trusted Passport root CA")
	fmt.Println("   - GlobalRegion (Storage's CA) and regional CAs share same root")

	// Optional: Display sample JWKS
	fmt.Println("\n=== Sample JWKS Output ===")
	fmt.Printf("Root CA (Passport) JWKS:\n%s\n\n", rootJWKS)
	fmt.Printf("GlobalRegion JWKS:\n%s\n\n", globalJWKS)
	fmt.Printf("Storage JWKS:\n%s\n", storageJWKS)

	// Prevent unused variable warnings
	_ = storagePriv
}
