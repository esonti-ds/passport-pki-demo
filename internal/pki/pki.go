package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// GenerateECDSAKey generates a new ECDSA private key using P-384 curve
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// CreateRootCA creates a self-signed root CA certificate
func CreateRootCA(name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
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

// CreateIntermediateCA creates an intermediate CA signed by the parent CA
func CreateIntermediateCA(name string, parentCert *x509.Certificate, parentPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // No further CAs
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

// CreateEndEntityCert creates an end-entity certificate signed by an intermediate CA
func CreateEndEntityCert(name string, interCert *x509.Certificate, interPriv *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
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
