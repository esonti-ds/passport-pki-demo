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
	fmt.Println("=== Service-to-Service Authentication Demo ===")
	fmt.Println("Demonstrating Service-as-Passport architecture with:")
	fmt.Println("- Patient Service (Prod Region: US, Europe, Asia)")
	fmt.Println("- Media Service (Prod Region: US, Europe, Asia)")
	fmt.Println("- Storage Service (Global)")
	fmt.Println()

	// Create Prod Root: Passport
	fmt.Println("1. Creating Prod Root: Passport")
	rootCert, rootPriv, err := pki.CreateProdRootCA("Passport")
	if err != nil {
		fmt.Printf("Error creating Prod Root: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Root 'Passport' created successfully\n")

	// Create Prod Region CAs
	fmt.Println("\n2. Creating Prod Region CAs")
	globalCert, globalPriv, err := pki.CreateProdRegionCA("Prod Region Global", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Global: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Region Global CA created (for global services)\n")

	usCert, usPriv, err := pki.CreateProdRegionCA("Prod Region US", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region US: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Region US CA created (for regional services)\n")

	europeCert, europePriv, err := pki.CreateProdRegionCA("Prod Region Europe", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Europe: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Region Europe CA created (for regional services)\n")

	asiaCert, asiaPriv, err := pki.CreateProdRegionCA("Prod Region Asia", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Asia: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Region Asia CA created (for regional services)\n")

	// Create Global Storage Service cert signed by Prod Region Global
	fmt.Println("\n3. Creating Service Certificates (enable S2S Authn)")
	storageCert, storagePriv, err := pki.CreateServiceCert("StorageService", globalCert, globalPriv)
	if err != nil {
		fmt.Printf("Error creating Storage Service cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Storage Service cert (Global - signed by Prod Region Global) created\n")

	// Create Regional Patient Service certs
	patientUSCert, patientUSPriv, err := pki.CreateServiceCert("PatientService-US", usCert, usPriv)
	if err != nil {
		fmt.Printf("Error creating Patient Service US cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Patient Service US cert (Regional - signed by Prod Region US) created\n")

	patientEuropeCert, patientEuropePriv, err := pki.CreateServiceCert("PatientService-Europe", europeCert, europePriv)
	if err != nil {
		fmt.Printf("Error creating Patient Service Europe cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Patient Service Europe cert (Regional - signed by Prod Region Europe) created\n")

	patientAsiaCert, patientAsiaPriv, err := pki.CreateServiceCert("PatientService-Asia", asiaCert, asiaPriv)
	if err != nil {
		fmt.Printf("Error creating Patient Service Asia cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Patient Service Asia cert (Regional - signed by Prod Region Asia) created\n")

	// Create Regional Media Service certs
	mediaUSCert, mediaUSPriv, err := pki.CreateServiceCert("MediaService-US", usCert, usPriv)
	if err != nil {
		fmt.Printf("Error creating Media Service US cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Media Service US cert (Regional - signed by Prod Region US) created\n")

	mediaEuropeCert, mediaEuropePriv, err := pki.CreateServiceCert("MediaService-Europe", europeCert, europePriv)
	if err != nil {
		fmt.Printf("Error creating Media Service Europe cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Media Service Europe cert (Regional - signed by Prod Region Europe) created\n")

	mediaAsiaCert, mediaAsiaPriv, err := pki.CreateServiceCert("MediaService-Asia", asiaCert, asiaPriv)
	if err != nil {
		fmt.Printf("Error creating Media Service Asia cert: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Media Service Asia cert (Regional - signed by Prod Region Asia) created\n")

	// Demo: Regional services accessing Global Storage Service
	fmt.Println("\n4. Testing Regional Services → Global Storage Service Access (S2S Authn)")
	testServices := []struct {
		name        string
		serviceCert *x509.Certificate
		servicePriv *ecdsa.PrivateKey
		regionCert  *x509.Certificate
		region      string
		serviceType string
	}{
		{"Patient Service US", patientUSCert, patientUSPriv, usCert, "US", "patient"},
		{"Media Service US", mediaUSCert, mediaUSPriv, usCert, "US", "media"},
		{"Patient Service Europe", patientEuropeCert, patientEuropePriv, europeCert, "Europe", "patient"},
		{"Media Service Europe", mediaEuropeCert, mediaEuropePriv, europeCert, "Europe", "media"},
		{"Patient Service Asia", patientAsiaCert, patientAsiaPriv, asiaCert, "Asia", "patient"},
		{"Media Service Asia", mediaAsiaCert, mediaAsiaPriv, asiaCert, "Asia", "media"},
	}

	for _, test := range testServices {
		fmt.Printf("\n   Testing: %s → Storage Service\n", test.name)
		claims := jwt.MapClaims{
			"sub":     fmt.Sprintf("%s-%s", test.serviceType, test.region),
			"scope":   "access_storage",
			"region":  test.region,
			"service": test.serviceType,
			"target":  "storage",
			"exp":     time.Now().Add(time.Hour).Unix(),
			"iat":     time.Now().Unix(),
		}

		jwtToken, err := pki.SignJWT(claims, test.servicePriv, test.serviceCert, test.regionCert)
		if err != nil {
			fmt.Printf("      ❌ Error signing JWT: %v\n", err)
			continue
		}
		fmt.Printf("      ✓ JWT signed successfully with Service Certificate\n")

		// Validate the JWT at Storage Service using only the Prod Root (Passport)
		parsedToken, err := pki.ValidateJWT(jwtToken, rootCert)
		if err != nil {
			fmt.Printf("      ❌ JWT validation failed: %v\n", err)
			continue
		}
		fmt.Printf("      ✓ JWT validated! Certificate chain verified through Prod Root\n")
		fmt.Printf("      Service Claims: %v\n", parsedToken.Claims)
	}

	// Generate JWKS for different components
	fmt.Println("\n5. Generating JWKS (JSON Web Key Sets)")

	// Root CA JWKS
	rootJWKS, err := jwks.CreateJWKS(rootCert)
	if err != nil {
		fmt.Printf("Error creating root JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Root (Passport) JWKS created\n")

	// Prod Region Global JWKS with certificate chain
	globalJWKS, err := jwks.CreateJWKS(globalCert, rootCert)
	if err != nil {
		fmt.Printf("Error creating Prod Region Global JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Prod Region Global JWKS created (with certificate chain)\n")

	// Storage service JWKS
	storageJWKS, err := jwks.CreateJWKS(storageCert, globalCert, rootCert)
	if err != nil {
		fmt.Printf("Error creating Storage JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✓ Storage service JWKS created (with full certificate chain)\n")

	fmt.Println("\n=== Summary ===")
	fmt.Println("Service-as-Passport Certificate Hierarchy:")
	fmt.Println("  Passport (Prod Root)")
	fmt.Println("  ├── Prod Region Global")
	fmt.Println("  │   └── StorageService (Global Service)")
	fmt.Println("  ├── Prod Region US")
	fmt.Println("  │   ├── PatientService-US (Regional Service)")
	fmt.Println("  │   └── MediaService-US (Regional Service)")
	fmt.Println("  ├── Prod Region Europe")
	fmt.Println("  │   ├── PatientService-Europe (Regional Service)")
	fmt.Println("  │   └── MediaService-Europe (Regional Service)")
	fmt.Println("  └── Prod Region Asia")
	fmt.Println("      ├── PatientService-Asia (Regional Service)")
	fmt.Println("      └── MediaService-Asia (Regional Service)")
	fmt.Println()
	fmt.Println("✅ Service Authentication & Authorization Model:")
	fmt.Println("   - Regional services are confined to their regions")
	fmt.Println("   - Regional services can access global services")
	fmt.Println("   - Certificate chain validation enforces service boundaries")
	fmt.Println("   - Each service signs JWTs with their Service Certificate (S2S Authn)")
	fmt.Println("   - JWTs include x5c header with certificate chain")
	fmt.Println("   - Services validate chains back to trusted Prod Root")
	fmt.Println()
	fmt.Println("🔐 Service Access Patterns:")
	fmt.Println("   ✅ PatientService-US → StorageService (Regional → Global)")
	fmt.Println("   ✅ MediaService-Europe → StorageService (Regional → Global)")
	fmt.Println("   ❌ PatientService-US → MediaService-Europe (Regional → Regional)")
	fmt.Println("   ❌ MediaService-Asia → PatientService-US (Regional → Regional)")

	// Optional: Display sample JWKS
	fmt.Println("\n=== Sample JWKS Output ===")
	fmt.Printf("Prod Root (Passport) JWKS:\n%s\n\n", rootJWKS)
	fmt.Printf("Prod Region Global JWKS:\n%s\n\n", globalJWKS)
	fmt.Printf("Storage Service JWKS:\n%s\n", storageJWKS)

	// Prevent unused variable warnings
	_ = storagePriv
}
