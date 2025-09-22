# Passport PKI Demo

A comprehensive demonstration of hierarchical Public Key Infrastructure (PKI) with JWT authentication, featuring both basic certificate chain validation and advanced user JWT embedding.

## 🏗️ Project Structure

```
passport-pki-demo/
├── cmd/                          # Command-line applications
│   ├── basic-demo/              # Basic PKI certificate chain demo
│   ├── enhanced-demo/           # Advanced demo with embedded user JWTs
│   └── jwt-inspector/           # Tool to inspect embedded JWTs
├── internal/                    # Internal packages (not for external use)
│   ├── pki/                     # Core PKI functionality
│   ├── userauth/                # User authentication and JWT embedding
│   └── jwks/                    # JSON Web Key Set utilities
├── examples/                    # Example code and demonstrations
├── docs/                        # Detailed documentation
└── README.md                    # This file
```

## 🎯 Features

### Core PKI Functionality
- ✅ Hierarchical certificate chain creation (Root → Intermediate → End Entity)
- ✅ Cross-region certificate validation
- ✅ JWKS (JSON Web Key Set) generation
- ✅ JWT signing with embedded certificate chains (x5c)
- ✅ Certificate chain validation

### Advanced User Authentication
- ✅ User JWT embedding in certificate extensions
- ✅ Two-layer security (Account certificates + User JWTs)
- ✅ Role-based access control (RBAC)
- ✅ Cross-region user context preservation
- ✅ Fine-grained authorization policies

## 🚀 Quick Start

### Prerequisites
- Go 1.24.6 or later
- No external dependencies except `github.com/golang-jwt/jwt/v5`

### Installation
```bash
git clone <repository-url>
cd passport-pki-demo
go mod tidy
```

### Run Basic Demo
```bash
go run cmd/basic-demo/main.go
```

### Run Enhanced Demo (with User JWTs)
```bash
go run cmd/enhanced-demo/main.go
```

### Inspect JWT Embeddings
```bash
go run cmd/jwt-inspector/main.go
```

## 📋 Certificate Hierarchy

```
Passport (Root CA)
├── GlobalRegion (Intermediate CA)
│   └── Storage (End Entity)
├── USRegion (Intermediate CA)  
│   └── Account-US (End Entity)
├── EuropeRegion (Intermediate CA)
│   └── Account-Europe (End Entity)
└── AsiaRegion (Intermediate CA)
    └── Account-Asia (End Entity)
```

## 🔐 Security Architecture

### Two-Layer Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Storage Service                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               JWT Validation                            │    │
│  │  1. Validate Account JWT signature                      │    │
│  │  2. Verify certificate chain → Passport root CA         │    │
│  │  3. Extract user JWT from certificate extension         │    │
│  │  4. Validate user JWT with UserAuth module              │    │
│  │  5. Apply user-based authorization rules                │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              ↑
                    Account JWT with x5c chain
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Account Service                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           Certificate Structure                         │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Account Certificate (x509)                     │    │    │
│  │  │  ├── Subject: Account-Alice (CompanyA)          │    │    │
│  │  │  ├── Signed by: USRegion CA                     │    │    │
│  │  │  └── Extensions:                                │    │    │
│  │  │      └── OID 1.3.6.1.4.1.999.1.1 (User JWT)     │    │    │
│  │  │          └── "eyJ0eXAiOiJKV1QiLCJhbGciOi..."    │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1: PKI Certificate Chain Authentication
- **Purpose**: Verify Account identity and regional authority
- **Method**: X.509 certificate chain validation
- **Trust Root**: Passport CA
- **Validates**: Account authenticity, regional membership, certificate integrity

### Layer 2: User JWT Authorization (Enhanced Demo)
- **Purpose**: Fine-grained user permissions and context
- **Method**: JWT embedded in certificate extension (OID 1.3.6.1.4.1.999.1.1)
- **Signed by**: Separate UserAuth module
- **Contains**: User ID, roles, tenant, permissions

## 📚 How It Works

### Basic PKI Flow
1. **Account signs JWT**: Uses regional certificate private key
2. **JWT includes x5c**: Certificate chain embedded in JWT header
3. **Storage validates**: Verifies certificate chain back to Passport root
4. **Access granted**: If chain is valid and JWT signature matches

### Enhanced Flow (with User JWTs)
1. **User JWT created**: Separate auth module creates user-specific JWT
2. **JWT embedded**: User JWT stored in Account certificate extension
3. **Account JWT signed**: Account service signs request with embedded user context
4. **Two-layer validation**: Storage validates both certificate chain AND user JWT
5. **Authorization applied**: User roles determine allowed actions

## 💼 Example Usage Scenarios

### Scenario 1: Cross-Region Admin Access
```
Alice (CompanyA Admin, US Region) → Storage (Global Region)
✅ Account: Valid USRegion → Passport chain
✅ User: Admin role allows read/write access
```

### Scenario 2: Limited User Access
```
Bob (CompanyB User, Europe Region) → Storage (Global Region)  
✅ Account: Valid EuropeRegion → Passport chain
⚠️  User: User role allows read-only access
```

### Scenario 3: Guest Access Denied
```
Charlie (CompanyC Guest, Asia Region) → Storage (Global Region)
✅ Account: Valid AsiaRegion → Passport chain
❌ User: Guest role has no storage permissions
```

## 🛠️ Development

### Adding New Regional CAs
```go
newRegionCert, newRegionPriv, err := pki.CreateIntermediateCA("NewRegion", rootCert, rootPriv)
```

### Creating User with Custom Roles
```go
user := userauth.User{
    ID:     "user-123",
    Email:  "user@company.com",
    Roles:  []string{"custom-role", "storage-read"},
    Tenant: "MyCompany",
    Region: "US",
}
```

### Custom Authorization Rules
```go
func CustomAuthorization(user *userauth.User, action string) bool {
    // Implement custom logic here
    return userauth.AuthorizeUserAction(user, action)
}
```

## 🌍 Real-World Applications

This architecture is ideal for:
- **Microservices**: Service-to-service authentication with user context
- **Multi-tenant SaaS**: Tenant isolation with user-level permissions
- **API Gateways**: Single token containing both identity and authorization
- **Zero Trust Networks**: Cryptographic identity + fine-grained access control
- **Enterprise PKI**: Scalable certificate management across regions
- **OAuth/OIDC Systems**: JWT validation with certificate backing

## 🔧 Configuration

### Custom OID for User JWT Extension
The project uses OID `1.3.6.1.4.1.999.1.1` for embedding user JWTs. This is a private enterprise OID suitable for demonstration purposes. In production, use your organization's assigned OID.

### Key Algorithms
- **Root/Intermediate CAs**: ECDSA P-384
- **End Entity Certificates**: ECDSA P-384
- **User JWTs**: ECDSA P-256 (separate key)
- **Certificate Validity**: Root (10 years), Intermediate (5 years), End Entity (1 year)

## 📖 Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - Detailed architecture explanation
- [`docs/SECURITY.md`](docs/SECURITY.md) - Security considerations and best practices
- [`docs/API.md`](docs/API.md) - API documentation for internal packages

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and demonstration purposes.

## 🆘 Troubleshooting

### Common Issues

**Certificate Validation Fails**
- Ensure certificate chains are properly constructed
- Check that the root CA is trusted
- Verify certificate dates (not expired)

**User JWT Not Found**
- Confirm the certificate includes the custom extension
- Check the OID matches `userauth.UserJWTExtensionOID`
- Verify the JWT was properly embedded during certificate creation

**Import Errors**
- Run `go mod tidy` to resolve dependencies
- Ensure you're using Go 1.24.6 or later
- Check that internal package imports use the correct module path
