# Service Passport Architecture

## Overview

The Passport PKI Demo implements a two-layer security architecture combining traditional PKI certificate chains with embedded user JWTs for fine-grained authorization. This creates "Service Passports" that enable both Service-to-Service Authentication (S2S Authn) and Service-to-Service Authentication + Authorization (S2S Authn + Authz).

## Visual Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    StorageService (Global)                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               Service Passport Validation               │    │
│  │  1. Validate Service Passport JWT signature             │    │
│  │  2. Verify certificate chain → Prod Root CA             │    │
│  │  3. Extract user JWT from Service Passport extension    │    │
│  │  4. Validate user JWT with S2S Auth+Authz module        │    │
│  │  5. Apply healthcare user-based authorization rules     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              ↑
                    Service Passport JWT with x5c chain
                              │
┌─────────────────────────────────────────────────────────────────┐
│                PatientService-US (Prod Region)                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           Service Passport Structure                    │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Service Certificate (x509)                     │    │    │
│  │  │  ├── Subject: PatientService-US (HospitalA)     │    │    │
│  │  │  ├── Signed by: Prod Region US CA               │    │    │
│  │  │  └── Extensions:                                │    │    │
│  │  │      └── OID 1.3.6.1.4.1.999.1.1 (User JWT)     │    │    │
│  │  │          └── "eyJ0eXAiOiJKV1QiLCJhbGciOi..."    │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                    Application Layer                              │
├───────────────────────────────────────────────────────────────────┤
│  cmd/s2s-authn-demo/ │  cmd/s2s-authn-user-  │  cmd/jwt-extractor-│
│  Basic S2S Authn     │  authz-demo/          │  demo/             │
│  Demo                │  S2S Authn+Authz Demo │  Service Passport  │
│                      │                       │  Analysis Tool     │
└───────────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────────┐
│                    Core Library Layer                             │
├───────────────────────────────────────────────────────────────────┤
│  internal/pki/       │  internal/s2s-auth-    │  internal/jwks/   │
│  Service Certificate │  authz/                │  JWKS Generation  │
│  Operations          │  Service Passport      │                   │
│                      │  Management            │                   │
└───────────────────────────────────────────────────────────────────┘
                              │
┌───────────────────────────────────────────────────────────────────┐
│                    External Dependencies                          │
├───────────────────────────────────────────────────────────────────┤
│  crypto/x509         │  crypto/ecdsa        │  golang-jwt/jwt     │
│  Standard Go PKI     │  Elliptic Curves     │  JWT Operations     │
└───────────────────────────────────────────────────────────────────┘
```

## Security Model

### Traditional PKI Layer (S2S Authentication)

**Purpose**: Service-level authentication and Prod Region authority validation

**Components**:
- Prod Root CA (Passport): The ultimate trust anchor
- Prod Region CAs: US, Europe, Asia, Global
- Service Certificates: Service certificates for individual services

**Flow**:
1. Service obtains Service Certificate from Prod Region CA
2. Prod Region CA certificate is signed by Prod Root CA
3. JWT is signed with Service private key
4. Certificate chain (x5c) is embedded in JWT header
5. StorageService validates chain back to trusted Prod Root

### Service Passport Layer (S2S Authentication + Authorization)

**Purpose**: User-level authorization and fine-grained healthcare permissions

**Components**:
- S2S Authentication + Authorization Module: Independent JWT signing authority
- User JWT: Contains user identity, healthcare roles, tenant information
- Service Certificate Extension: Custom OID stores user JWT in Service Certificate

**Flow**:
1. S2S Auth+Authz module creates healthcare user-specific JWT
2. User JWT is embedded in Service Certificate as extension (creates Service Passport)
3. Service Passport JWT includes certificate with embedded user JWT
4. StorageService extracts and validates both layers independently
5. Healthcare user roles determine allowed medical operations

## Validation Workflow

### StorageService Process:
1. **Receive Service Passport JWT**: With x5c header containing certificate chain
2. **Validate Service Certificate Chain**: Verify chain back to trusted Prod Root CA
3. **Extract Leaf Service Certificate**: Get Service Certificate from x5c[0]
4. **Find User JWT Extension**: Look for OID 1.3.6.1.4.1.999.1.1
5. **Validate User JWT**: Use S2S Auth+Authz module to verify user token
6. **Apply Healthcare Authorization**: Check user healthcare roles against requested medical action

## Data Structures

### Service Certificate Extensions (Service Passport)

```go
// Custom OID for user JWT storage in Service Passports
var UserJWTExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 999, 1, 1}

// Extension structure for Service Passport
userJWTExtension := pkix.Extension{
    Id:       UserJWTExtensionOID,
    Critical: false,           // Non-critical extension
    Value:    []byte(userJWT), // Raw JWT string
}
```

### Healthcare User Information

```go
type User struct {
    ID     string   `json:"id"`     // Unique healthcare user identifier
    Email  string   `json:"email"`  // Healthcare user email address
    Roles  []string `json:"roles"`  // List of healthcare user roles
    Tenant string   `json:"tenant"` // Healthcare organization
    Region string   `json:"region"` // User's home Prod Region
}
```

### JWT Claims Structure

**Service Passport JWT Claims**:
```json
{
  "sub": "service-session-id",
  "scope": "access_storage",
  "action": "read",
  "user_id": "dr-alice-123",
  "user_email": "alice.doctor@hospital.com",
  "user_tenant": "HospitalA",
  "has_embedded_user_auth": true,
  "passport_type": "service_with_user_context",
  "auth_type": "s2s_authentication_authorization",
  "exp": 1758637697,
  "iat": 1758551297
}
```

**User JWT Claims** (embedded in Service Passport):
```json
{
  "sub": "dr-alice-123",
  "email": "alice.doctor@hospital.com",
  "roles": ["doctor", "patient-read", "patient-write", "storage-read", "storage-write"],
  "tenant": "HospitalA",
  "region": "US",
  "iss": "UserAuthService",
  "aud": "Storage",
  "exp": 1758637697,
  "iat": 1758551297,
  "scope": "user_authorization"
}
```

## Trust Model

### PKI Trust Chain
```
Prod Root CA (Self-signed)
    ├── Prod Region US CA (Signed by Passport)
    │   ├── PatientService-US Certificate (Signed by Prod Region US)
    │   └── MediaService-US Certificate (Signed by Prod Region US)
    ├── Prod Region Europe CA (Signed by Passport)
    │   ├── PatientService-Europe Certificate (Signed by Prod Region Europe)
    │   └── MediaService-Europe Certificate (Signed by Prod Region Europe)
    ├── Prod Region Asia CA (Signed by Passport)
    │   ├── PatientService-Asia Certificate (Signed by Prod Region Asia)
    │   └── MediaService-Asia Certificate (Signed by Prod Region Asia)
    └── Prod Region Global CA (Signed by Passport)
        └── StorageService Certificate (Signed by Prod Region Global)
```

### User Authentication Trust
```
S2S Authentication + Authorization Module (Independent Key Pair)
    ├── Signs User JWTs for all healthcare users
    ├── Validates extracted User JWTs from Service Passports
    └── Provides healthcare authorization decisions
```


## Module Responsibilities

### `internal/pki`
- Service Certificate creation and management
- JWT signing with Service Certificate chains
- Service Certificate chain validation
- Core PKI operations for S2S Authentication

### `internal/s2s-auth-authz`  
- User JWT creation and validation for healthcare users
- Service Certificate extension management (Service Passport creation)
- Healthcare user authorization logic
- Service Passport creation with embedded user context using `CreateServicePassport()`
- Service Passport JWT extraction using `ExtractUserJWTFromServicePassport()`
- Service Passport JWT creation using `CreateServicePassportJWT()`
- Service Passport validation using `ValidateServicePassportAndExtractUser()`

### `internal/jwks`
- JWKS format generation for Service Certificates
- Public key extraction and encoding
- Service Certificate chain encoding for JWKS

### Command Applications
- **s2s-authn-demo**: Demonstrates pure PKI Service Certificate chain validation (S2S Authentication)
- **s2s-authn-user-authz-demo**: Shows two-layer security with embedded user JWTs (S2S Authentication + Authorization via Service Passports)
- **jwt-extractor-demo**: Utility for examining Service Certificate extensions and embedded JWTs in Service Passports

## Key Function Reference

### Service Passport Creation
```go
// Create a Service Passport (Service Certificate with embedded User JWT)
serviceCert, servicePriv, err := s2sauthz.CreateServicePassport(
    serviceName, user, userJWT, prodRegionCert, prodRegionPriv)

// Create Service Passport JWT with user context
servicePassportJWT, err := s2sauthz.CreateServicePassportJWT(
    claims, user, servicePriv, serviceCert, prodRegionCert)
```

### Service Passport Validation
```go
// Validate Service Passport and extract user context
servicePassportToken, user, userJWT, err := s2sauthz.ValidateServicePassportAndExtractUser(
    signedToken, prodRootCert, userAuthModule)

// Extract User JWT from Service Passport certificate
userJWT, err := s2sauthz.ExtractUserJWTFromServicePassport(serviceCert)
```