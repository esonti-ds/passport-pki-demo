# Project Architecture

## Overview

The Passport PKI Demo implements a two-layer security architecture combining traditional PKI certificate chains with embedded user JWTs for fine-grained authorization.

## Visual Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Storage Service                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               JWT Validation                            │   │
│  │  1. Validate Account JWT signature                     │   │
│  │  2. Verify certificate chain → Passport root CA       │   │
│  │  3. Extract user JWT from certificate extension       │   │
│  │  4. Validate user JWT with UserAuth module            │   │
│  │  5. Apply user-based authorization rules              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↑
                    Account JWT with x5c chain
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Account Service                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Certificate Structure                         │   │
│  │  ┌─────────────────────────────────────────────────┐   │   │
│  │  │  Account Certificate (x509)                     │   │   │
│  │  │  ├── Subject: Account-Alice (CompanyA)          │   │   │
│  │  │  ├── Signed by: USRegion CA                     │   │   │
│  │  │  └── Extensions:                                │   │   │
│  │  │      └── OID 1.3.6.1.4.1.999.1.1 (User JWT)   │   │   │
│  │  │          └── "eyJ0eXAiOiJKV1QiLCJhbGciOi..."    │   │   │
│  │  └─────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
├─────────────────────────────────────────────────────────────────┤
│  cmd/basic-demo/     │  cmd/enhanced-demo/  │  cmd/jwt-inspector/ │
│  Basic PKI Demo      │  Enhanced User Demo  │  JWT Analysis Tool  │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Core Library Layer                          │
├─────────────────────────────────────────────────────────────────┤
│  internal/pki/       │  internal/userauth/  │  internal/jwks/     │
│  Certificate Ops    │  User JWT Embedding  │  JWKS Generation    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    External Dependencies                       │
├─────────────────────────────────────────────────────────────────┤
│  crypto/x509         │  crypto/ecdsa        │  golang-jwt/jwt     │
│  Standard Go PKI     │  Elliptic Curves     │  JWT Operations     │
└─────────────────────────────────────────────────────────────────┘
```

## Security Model

### Traditional PKI Layer (Layer 1)

**Purpose**: Account-level authentication and regional authority validation

**Components**:
- Root CA (Passport): The ultimate trust anchor
- Regional Intermediate CAs: USRegion, EuropeRegion, AsiaRegion, GlobalRegion
- End Entity Certificates: Account certificates and Storage certificate

**Flow**:
1. Account obtains certificate from regional CA
2. Regional CA certificate is signed by Passport root CA
3. JWT is signed with Account private key
4. Certificate chain (x5c) is embedded in JWT header
5. Storage validates chain back to trusted Passport root

### User JWT Layer (Layer 2)

**Purpose**: User-level authorization and fine-grained permissions

**Components**:
- UserAuth Module: Independent JWT signing authority
- User JWT: Contains user identity, roles, tenant information
- Certificate Extension: Custom OID stores user JWT in Account certificate

**Flow**:
1. UserAuth module creates user-specific JWT
2. User JWT is embedded in Account certificate as extension
3. Account JWT includes certificate with embedded user JWT
4. Storage extracts and validates both layers independently
5. User roles determine allowed operations

## Validation Workflow

### Storage Service Process:
1. **Receive Account JWT**: With x5c header containing certificate chain
2. **Validate Certificate Chain**: Verify chain back to trusted Passport root CA
3. **Extract Leaf Certificate**: Get Account certificate from x5c[0]
4. **Find User JWT Extension**: Look for OID 1.3.6.1.4.1.999.1.1
5. **Validate User JWT**: Use UserAuth module to verify user token
6. **Apply Authorization**: Check user roles against requested action

## Data Structures

### Certificate Extensions

```go
// Custom OID for user JWT storage
var UserJWTExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 999, 1, 1}

// Extension structure
userJWTExtension := pkix.Extension{
    Id:       UserJWTExtensionOID,
    Critical: false,           // Non-critical extension
    Value:    []byte(userJWT), // Raw JWT string
}
```

### User Information

```go
type User struct {
    ID     string   `json:"id"`     // Unique user identifier
    Email  string   `json:"email"`  // User email address
    Roles  []string `json:"roles"`  // List of user roles
    Tenant string   `json:"tenant"` // Tenant/organization
    Region string   `json:"region"` // User's home region
}
```

### JWT Claims Structure

**Account JWT Claims**:
```json
{
  "sub": "account-session-id",
  "scope": "access_storage",
  "action": "read",
  "user_id": "alice-123",
  "user_email": "alice@company.com",
  "user_tenant": "CompanyA",
  "has_embedded_user_auth": true,
  "exp": 1758637697,
  "iat": 1758551297
}
```

**User JWT Claims** (embedded in certificate):
```json
{
  "sub": "alice-123",
  "email": "alice@company.com",
  "roles": ["admin", "storage-read", "storage-write"],
  "tenant": "CompanyA",
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
Passport Root CA (Self-signed)
    ├── USRegion CA (Signed by Passport)
    │   └── Account-US Certificate (Signed by USRegion)
    ├── EuropeRegion CA (Signed by Passport)
    │   └── Account-Europe Certificate (Signed by EuropeRegion)
    ├── AsiaRegion CA (Signed by Passport)
    │   └── Account-Asia Certificate (Signed by AsiaRegion)
    └── GlobalRegion CA (Signed by Passport)
        └── Storage Certificate (Signed by GlobalRegion)
```

### User Authentication Trust
```
UserAuth Module (Independent Key Pair)
    ├── Signs User JWTs for all users
    ├── Validates extracted User JWTs
    └── Provides authorization decisions
```

## Cross-Region Access Pattern

**Scenario**: Alice (US Account) accessing Storage (Global)

1. **Certificate Validation**:
   - Alice's certificate signed by USRegion CA
   - USRegion CA signed by Passport root CA
   - Storage certificate signed by GlobalRegion CA  
   - GlobalRegion CA signed by Passport root CA
   - **Result**: Both chains trace to same Passport root → Trust established

2. **User Context Preservation**:
   - Alice's user JWT embedded in US certificate
   - JWT contains Alice's roles and tenant information
   - Storage extracts user context regardless of regional boundaries
   - **Result**: User-level permissions apply globally

## Module Responsibilities

### `internal/pki`
- Certificate creation and management
- JWT signing with certificate chains
- Certificate chain validation
- Core PKI operations

### `internal/userauth`  
- User JWT creation and validation
- Certificate extension management
- User authorization logic
- Account certificate creation with embedded user context

### `internal/jwks`
- JWKS format generation
- Public key extraction and encoding
- Certificate chain encoding for JWKS

### Command Applications
- **basic-demo**: Demonstrates pure PKI certificate chain validation
- **enhanced-demo**: Shows two-layer security with embedded user JWTs
- **jwt-inspector**: Utility for examining certificate extensions and embedded JWTs

## Scalability Considerations

### Regional Scaling
- New regions: Add new intermediate CA under Passport root
- Regional independence: Each region manages its own account certificates
- Cross-region access: Automatic via shared root trust

### User Scaling  
- User management: Independent of PKI certificate lifecycle
- Role updates: Change user JWT without certificate reissuance
- Tenant isolation: User JWTs include tenant context

### Performance Optimization
- Certificate caching: Cache validated certificate chains
- JWT reuse: User JWTs have independent expiration from account certificates
- Validation shortcuts: Skip redundant chain validations for known good certificates
