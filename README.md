# Passport PKI Demo Suite

This repository contains three comprehensive demos that showcase a two-layer security architecture combining PKI certificates for Service-to-Service Authentication and Service Passports (Service Certificates with embedded User JWTs) for enterprise-grade authentication and authorization.

## Demo Naming Convention

The demos follow a clear naming pattern that reflects their functional purpose:

- **`s2s-authn-demo`**: **Service-to-Service Authentication** - Basic PKI certificate chain validation (S2S Authn)
- **`s2s-authn-user-authz-demo`**: **Service-to-Service Authentication + User Authorization** - PKI + embedded user JWTs (S2S Authn + Authz via Service Passports)
- **`jwt-extractor-demo`**: **JWT Extraction Tool** - Technical inspection of Service Passport JWT mechanisms

## Overview

The demo suite demonstrates a distributed service architecture with:
- **Patient Service** (Prod Region - US/Europe/Asia)
- **Media Service** (Prod Region - US/Europe/Asia) 
- **Storage Service** (Global)

### Two-Layer Security Model:
- **Layer 1**: Service Certificate Chain (S2S Authn)
  - Prod Region services are confined to their respective regions
  - Prod Region services can access global services
  - Certificate chain validation enforces access boundaries
- **Layer 2**: Service Passports with Embedded User JWT (S2S Authn + Authz)
  - Fine-grained resource permissions per user
  - Role-based access control across services
  - User context preserved across service boundaries

This architecture enables scalable, cross-Prod Region service access control with fine-grained user permissions.

## Demo Descriptions

### 🏗️ Service-to-Service Authentication Demo (`cmd/s2s-authn-demo/main.go`)

**Purpose**: Fundamental PKI certificate chain creation and validation for healthcare services (S2S Authn)

**What it demonstrates**:
- Complete PKI hierarchy creation: Passport (Prod Root) → Prod Region CAs → Healthcare Services
- Cross-region access where Prod Region healthcare services can access global Storage services
- JWKS (JSON Web Key Sets) generation for each certificate authority
- Certificate chain validation back to trusted Prod Root

**Service Architecture**:
```
Passport (Prod Root)
├── Prod Region Global → StorageService (Global)
├── Prod Region US → PatientService-US, MediaService-US (Regional)
├── Prod Region Europe → PatientService-Europe, MediaService-Europe (Regional)
└── Prod Region Asia → PatientService-Asia, MediaService-Asia (Regional)
```

**Key Features**:
- ✅ Regional certificate authorities for distributed healthcare management
- ✅ Cross-region JWT validation through shared root CA
- ✅ JWKS generation for service discovery
- ✅ End-to-end certificate chain verification
- ✅ Service-as-Passport authentication model

### 🔐 Service-to-Service Authentication + User Authorization Demo (`cmd/s2s-authn-user-authz-demo/main.go`)

**Purpose**: Two-layer security architecture with healthcare PKI + embedded user JWTs

**What it demonstrates**:
- Healthcare user profile creation with medical roles and tenant assignments
- Embedding user JWTs into healthcare service certificates as X.509 extensions
- Role-based access control through JWT validation for medical scenarios
- Separation of service authentication (PKI) vs user authorization (JWT)

**Sample Healthcare Users & Access Results**:
- **Alice (Doctor)**: ✅ Full patient data read/write access (HospitalA, doctor privileges)
- **Bob (Nurse)**: ✅ Patient read + media access (ClinicB, nurse privileges) 
- **Charlie (Patient)**: ✅ Limited own data access (PatientPortal, patient privileges)

**Key Features**:
- ✅ User JWT embedding in healthcare service certificate extensions
- ✅ Fine-grained medical role-based access control
- ✅ Multi-tenant support with regional healthcare distribution
- ✅ Comprehensive healthcare authorization testing scenarios
- ✅ HIPAA-compliant user context preservation

### 🔍 JWT Extractor Demo (`cmd/jwt-extractor-demo/main.go`)

**Purpose**: Technical inspection and analysis of embedded JWT extraction for healthcare services

**What it demonstrates**:
- JWT embedding mechanism in X.509 healthcare service certificate extensions
- JWT extraction and validation process from healthcare service certificates
- Healthcare user JWT content decoding and analysis
- Certificate extension inspection and identification

**Technical Details**:
- **Custom OID**: `1.3.6.1.4.1.999.1.1` for User JWT extension
- **JWT Contents**: Healthcare user ID, email, medical roles, tenant, region, expiration
- **Extension Analysis**: Identifies and explains certificate extensions
- **Validation Workflow**: Step-by-step JWT extraction process for healthcare services

**Key Features**:
- ✅ Healthcare JWT embedding/extraction demonstration
- ✅ Medical service certificate extension analysis
- ✅ Healthcare user JWT content inspection and decoding
- ✅ Healthcare service integration workflow documentation

## How to Run the Demos

### Prerequisites

- Go 1.24.6 or later
- This repository cloned locally

### Running Individual Demos

#### Service-to-Service Authentication Demo
```bash
cd /path/to/passport-pki-demo
go run cmd/s2s-authn-demo/main.go
```

#### Service-to-Service Authentication + User Authorization Demo
```bash
cd /path/to/passport-pki-demo
go run cmd/s2s-authn-user-authz-demo/main.go
```

#### JWT Extractor Demo
```bash
cd /path/to/passport-pki-demo
go run cmd/jwt-extractor-demo/main.go
```

### Running All Demos
```bash
# Run all demos sequentially
go run cmd/s2s-authn-demo/main.go
go run cmd/s2s-authn-user-authz-demo/main.go
go run cmd/jwt-extractor-demo/main.go
```

## Expected Output Summary

### Service-to-Service Authentication Demo Output
- Healthcare PKI hierarchy creation with regional CAs
- Cross-region healthcare service JWT signing and validation
- JWKS generation for healthcare service discovery
- Certificate chain verification success messages
- Service-as-Passport authentication demonstrations

### Service-to-Service Authentication + User Authorization Demo Output
- Healthcare user authentication module initialization
- Sample healthcare user creation with medical role assignments
- Healthcare service certificate creation with embedded JWTs
- Healthcare access scenario testing with permission results
- Healthcare service architecture benefits summary

### JWT Extractor Demo Output
- Demo healthcare service certificate creation with embedded JWT
- JWT extraction and validation confirmation
- Decoded JWT header and payload contents showing healthcare roles
- Certificate extension analysis and identification
- Healthcare service integration workflow explanation

## Architecture Benefits

The complete demo suite showcases a healthcare-focused Service-as-Passport architecture:

1. **� Scalable Healthcare PKI Infrastructure**: Regional CAs enable distributed healthcare certificate management
2. **🌐 Cross-Region Medical Services Authentication**: Regional healthcare services can access global storage services
3. **�‍⚕️ Fine-Grained Medical Authorization**: User JWTs provide individual-level access control for healthcare roles
4. **🔄 Separation of Concerns**: PKI handles service identity, JWTs handle user medical permissions
5. **📋 Standards Compliance**: Uses standard X.509 extensions and JWT formats for healthcare interoperability
6. **�️ Healthcare Storage Integration**: Clear workflow for medical services to extract and use user context

## Healthcare Service Architecture Patterns

### Service Authentication (Layer 1 - PKI)
- **Regional Services**: PatientService, MediaService (confined to their regions)
- **Global Services**: StorageService (accessible by all regional services)
- **Certificate Validation**: Regional services must present valid certificates from their regional CA
- **Access Control**: Regional services cannot directly access other regional services

### User Authorization (Layer 2 - Embedded JWT)
- **Medical Roles**: Doctor, Nurse, Patient, Admin
- **Resource Permissions**: patient-read, patient-write, media-read, storage-read, storage-write
- **HIPAA Compliance**: User context preserved across service boundaries
- **Tenant Isolation**: Hospital, Clinic, PatientPortal organizational boundaries

## Use Cases

This healthcare Service-as-Passport architecture is ideal for:

- **Healthcare environments** requiring both service and user-level security
- **Multi-region medical deployments** with centralized authentication
- **Medical storage services** needing fine-grained access control
- **Healthcare microservices architectures** requiring embedded user context
- **HIPAA compliance scenarios** demanding certificate-based authentication
- **Telemedicine platforms** with cross-region patient data access
- **Medical imaging services** requiring role-based authorization
- **Electronic Health Record (EHR) systems** with multi-tenant support

## Security Features

- ✅ **Certificate Chain Validation**: Cryptographic verification back to root CA
- ✅ **Regional Authenticity**: Certificate authorities bound to specific regions
- ✅ **User Context Preservation**: Individual user information embedded in certificates
- ✅ **Role-Based Access Control**: Fine-grained permissions through JWT claims
- ✅ **Cross-Region Support**: Unified authentication across distributed infrastructure
- ✅ **Tenant Isolation**: Multi-tenant support with organizational boundaries

## Next Steps

After running the demos, you can:

1. **Explore the Code**: Examine the internal packages (`internal/pki`, `internal/s2s-auth-authz`, `internal/jwks`)
2. **Customize Users**: Modify user roles and permissions in the enhanced demo
3. **Extend Regions**: Add new regional CAs to the PKI hierarchy
4. **Integration Testing**: Implement the architecture in your own services
5. **Security Analysis**: Review the cryptographic implementations and security models

For technical implementation details, see the source code in the `internal/` directory and the comprehensive examples provided.
