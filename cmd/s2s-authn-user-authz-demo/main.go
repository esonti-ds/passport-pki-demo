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

	s2sauthz "passport-pki-demo/internal/s2s-auth-authz"

	"github.com/golang-jwt/jwt/v5"
)

// Helper functions from main.go (simplified for this demo)
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func createProdRootCA(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
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

func createProdRegionCA(regionName string, prodRootCert *x509.Certificate, prodRootPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := generateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: regionName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, prodRootCert, priv.Public(), prodRootPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func createServiceCert(name string, interCert *x509.Certificate, interPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
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
	fmt.Println("=== Service-to-Service Authentication + User Authorization Demo ===")
	fmt.Println("Demonstrating two-layer security architecture:")
	fmt.Println("- Layer 1: S2S Authn via Service Certificates")
	fmt.Println("- Layer 2: User Authz via Service Passports (Service Certs + User JWTs)")
	fmt.Println()

	// Step 1: Initialize User Authentication Module
	fmt.Println("1. Initializing User Authentication Module")
	userAuthModule, err := s2sauthz.NewUserAuthModule()
	if err != nil {
		fmt.Printf("Error creating user auth module: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   ✓ User authentication module ready")

	// Step 2: Create Sample Users with Healthcare-relevant roles
	fmt.Println("\n2. Creating Sample Healthcare Users")
	alice := s2sauthz.User{
		ID:     "alice-123",
		Email:  "alice.doctor@hospital.com",
		Roles:  []string{"doctor", "patient-read", "patient-write", "media-read", "storage-read", "storage-write"},
		Tenant: "HospitalA",
		Region: "US",
	}

	bob := s2sauthz.User{
		ID:     "bob-456",
		Email:  "bob.nurse@clinic.com",
		Roles:  []string{"nurse", "patient-read", "media-read", "storage-read"},
		Tenant: "ClinicB",
		Region: "Europe",
	}

	charlie := s2sauthz.User{
		ID:     "charlie-789",
		Email:  "charlie.patient@email.com",
		Roles:  []string{"patient", "media-read"},
		Tenant: "PatientPortal",
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

	fmt.Printf("   ✓ Alice (doctor, %s) - User JWT created\n", alice.Tenant)
	fmt.Printf("   ✓ Bob (nurse, %s) - User JWT created\n", bob.Tenant)
	fmt.Printf("   ✓ Charlie (patient, %s) - User JWT created\n", charlie.Tenant)

	// Step 3: Create PKI Infrastructure for Healthcare Services
	fmt.Println("\n3. Creating PKI Infrastructure for Healthcare Services")
	rootCert, rootPriv, err := createProdRootCA("Passport")
	if err != nil {
		fmt.Printf("Error creating Prod Root: %v\n", err)
		os.Exit(1)
	}

	// Regional Prod Region CAs
	usRegion, usRegionPriv, err := createProdRegionCA("Prod Region US", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region US: %v\n", err)
		os.Exit(1)
	}

	europeRegion, europeRegionPriv, err := createProdRegionCA("Prod Region Europe", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Europe: %v\n", err)
		os.Exit(1)
	}

	asiaRegion, asiaRegionPriv, err := createProdRegionCA("Prod Region Asia", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Asia: %v\n", err)
		os.Exit(1)
	}

	globalRegion, globalRegionPriv, err := createProdRegionCA("Prod Region Global", rootCert, rootPriv)
	if err != nil {
		fmt.Printf("Error creating Prod Region Global: %v\n", err)
		os.Exit(1)
	}

	// Global Storage Service certificate
	storageCert, _, err := createServiceCert("StorageService", globalRegion, globalRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Storage Service cert: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("   ✓ PKI hierarchy created for healthcare services:")
	fmt.Println("     - Global: StorageService")
	fmt.Println("     - Prod Region CAs: US, Europe, Asia, Global")

	// Step 4: Create Service Passports (Service Certificates with Embedded User JWTs for S2S Authn + Authz)
	fmt.Println("\n4. Creating Service Passports (Service Certificates + User JWTs for S2S Authn + Authz)")

	aliceServiceCert, aliceServicePriv, err := s2sauthz.CreateServicePassport("PatientService-US-Alice", alice, aliceUserJWT, usRegion, usRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Alice's Service Passport: %v\n", err)
		os.Exit(1)
	}

	bobServiceCert, bobServicePriv, err := s2sauthz.CreateServicePassport("MediaService-Europe-Bob", bob, bobUserJWT, europeRegion, europeRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Bob's Service Passport: %v\n", err)
		os.Exit(1)
	}

	charlieServiceCert, charlieServicePriv, err := s2sauthz.CreateServicePassport("PatientPortal-Asia-Charlie", charlie, charlieUserJWT, asiaRegion, asiaRegionPriv)
	if err != nil {
		fmt.Printf("Error creating Charlie's Service Passport: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("   ✓ Alice's Service Passport (PatientService-US) + embedded user JWT")
	fmt.Println("   ✓ Bob's Service Passport (MediaService-Europe) + embedded user JWT")
	fmt.Println("   ✓ Charlie's Service Passport (PatientPortal-Asia) + embedded user JWT")

	// Step 5: Test Healthcare Access Scenarios
	fmt.Println("\n5. Testing Healthcare Service Access Scenarios")

	// Test 1: Alice (doctor) tries to access patient data through PatientService
	fmt.Println("\n   Test 1: Alice (Doctor) - Patient Data Access via PatientService")
	aliceClaims := jwt.MapClaims{
		"sub":      "alice-session",
		"scope":    "access_patient_data",
		"service":  "patient",
		"action":   "read_write",
		"resource": "patient_records",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}

	aliceJWT, err := s2sauthz.CreateServicePassportJWT(aliceClaims, alice, aliceServicePriv, aliceServiceCert, usRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Alice's JWT: %v\n", err)
	} else {
		// Storage validates the Service Passport JWT and extracts user info
		_, extractedUser, userJWT, err := s2sauthz.ValidateServicePassportAndExtractUser(aliceJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Service Passport validation failed: %v\n", err)
		} else {
			fmt.Printf("      ✅ Service Passport JWT validated successfully (S2S Authn + Authz)\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Role: Doctor, Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Permissions: %v\n", extractedUser.Roles)

			// Check specific permissions
			canReadPatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-read")
			canWritePatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-write")
			canAccessStorage := s2sauthz.AuthorizeUserAction(extractedUser, "storage-read")
			fmt.Printf("         Patient read permission: %v\n", canReadPatients)
			fmt.Printf("         Patient write permission: %v\n", canWritePatients)
			fmt.Printf("         Storage access permission: %v\n", canAccessStorage)
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
		}
	}

	// Test 2: Bob (nurse) tries to access media through MediaService
	fmt.Println("\n   Test 2: Bob (Nurse) - Medical Media Access via MediaService")
	bobClaims := jwt.MapClaims{
		"sub":      "bob-session",
		"scope":    "access_medical_media",
		"service":  "media",
		"action":   "read",
		"resource": "medical_images",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}

	bobJWT, err := s2sauthz.CreateServicePassportJWT(bobClaims, bob, bobServicePriv, bobServiceCert, europeRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Bob's JWT: %v\n", err)
	} else {
		_, extractedUser, userJWT, err := s2sauthz.ValidateServicePassportAndExtractUser(bobJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Service Passport validation failed: %v\n", err)
		} else {
			fmt.Printf("      ✅ Service Passport JWT validated successfully (S2S Authn + Authz)\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Role: Nurse, Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Permissions: %v\n", extractedUser.Roles)

			canReadPatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-read")
			canReadMedia := s2sauthz.AuthorizeUserAction(extractedUser, "media-read")
			canWritePatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-write")
			fmt.Printf("         Patient read permission: %v\n", canReadPatients)
			fmt.Printf("         Media read permission: %v\n", canReadMedia)
			fmt.Printf("         Patient write permission: %v\n", canWritePatients)
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
		}
	}

	// Test 3: Charlie (patient) tries to access own data
	fmt.Println("\n   Test 3: Charlie (Patient) - Own Data Access via PatientPortal")
	charlieClaims := jwt.MapClaims{
		"sub":      "charlie-session",
		"scope":    "access_own_data",
		"service":  "patient_portal",
		"action":   "read",
		"resource": "own_records",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}

	charlieJWT, err := s2sauthz.CreateServicePassportJWT(charlieClaims, charlie, charlieServicePriv, charlieServiceCert, asiaRegion)
	if err != nil {
		fmt.Printf("      ❌ Error signing Charlie's JWT: %v\n", err)
	} else {
		_, extractedUser, userJWT, err := s2sauthz.ValidateServicePassportAndExtractUser(charlieJWT, rootCert, userAuthModule)
		if err != nil {
			fmt.Printf("      ❌ Service Passport validation failed: %v\n", err)
		} else {
			fmt.Printf("      ✅ Service Passport JWT validated successfully (S2S Authn + Authz)\n")
			fmt.Printf("      ✅ User JWT extracted and validated\n")
			fmt.Printf("         User: %s (%s)\n", extractedUser.Email, extractedUser.ID)
			fmt.Printf("         Role: Patient, Tenant: %s\n", extractedUser.Tenant)
			fmt.Printf("         Permissions: %v\n", extractedUser.Roles)

			canReadMedia := s2sauthz.AuthorizeUserAction(extractedUser, "media-read")
			canReadPatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-read")
			canWritePatients := s2sauthz.AuthorizeUserAction(extractedUser, "patient-write")
			fmt.Printf("         Media read permission: %v\n", canReadMedia)
			fmt.Printf("         Patient read permission: %v\n", canReadPatients)
			fmt.Printf("         Patient write permission: %v\n", canWritePatients)
			fmt.Printf("         Embedded user JWT length: %d characters\n", len(userJWT))
		}
	}

	fmt.Println("\n=== Healthcare Service Architecture Summary ===")
	fmt.Println("🏗️ Two-Layer Security Architecture for Healthcare:")
	fmt.Println("   Layer 1: S2S Authn (Service Certificate Chain)")
	fmt.Println("     - Validates Service certificates against Prod Root")
	fmt.Println("     - Ensures Prod Region service authenticity")
	fmt.Println("     - Cryptographically verifies certificate chain")
	fmt.Println()
	fmt.Println("   Layer 2: S2S Authn + Authz (Service Passports with User JWTs)")
	fmt.Println("     - User JWT embedded in Service certificate extension")
	fmt.Println("     - Extracted and validated by separate auth module")
	fmt.Println("     - Healthcare role-based access control")
	fmt.Println()
	fmt.Println("🔐 Healthcare Service Benefits:")
	fmt.Println("   ✓ Service certificates prove Prod Region/organizational identity")
	fmt.Println("   ✓ Service Passports provide individual healthcare role authorization")
	fmt.Println("   ✓ Storage can extract user context for HIPAA compliance")
	fmt.Println("   ✓ Cross-region access with user-level permissions")
	fmt.Println("   ✓ Separation of concerns (Service PKI vs User auth)")
	fmt.Println("   ✓ Scalable across healthcare Prod Regions and organizations")
	fmt.Println()
	fmt.Println("🏥 Service Access Patterns:")
	fmt.Println("   ✅ PatientService (Prod Region) → StorageService (Global)")
	fmt.Println("   ✅ MediaService (Prod Region) → StorageService (Global)")
	fmt.Println("   ✅ PatientPortal (Prod Region) → StorageService (Global)")
	fmt.Println("   ❌ PatientService-US → MediaService-Europe (Prod Region → Prod Region)")

	// Prevent unused variable warnings
	_ = storageCert
}
