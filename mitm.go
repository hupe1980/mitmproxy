package mitmproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // nolint: gosec // ok
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/hupe1980/golog"
)

type CertTemplateGenFunc func(serial *big.Int, ski []byte, hostname, organization string, validity time.Duration) *x509.Certificate

type MITMOptions struct {
	// Organization (will be used for generated certificates)
	Organization string

	// Validity of the generated certificates
	Validity time.Duration

	// Storage for generated certificates
	CertStorage CertStorage

	CertTemplateGen CertTemplateGenFunc

	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger
}

// MITMConfig is a set of configuration values that are used to build TLS configs
// capable of MITM.
type MITMConfig struct {
	ca           *x509.Certificate // Root certificate authority
	caPrivateKey crypto.PrivateKey // CA private key

	// roots is a CertPool that contains the root CA GetOrCreateCert
	// it serves a single purpose -- to verify the cached domain certs
	roots           *x509.CertPool
	privateKey      crypto.Signer
	validity        time.Duration
	keyID           []byte // SKI to use in generated certificates (https://tools.ietf.org/html/rfc3280#section-4.2.1.2)
	organization    string
	certStorage     CertStorage
	certTemplateGen CertTemplateGenFunc
	logger          golog.Logger
}

// NewMITMConfig creates a new MITM configuration
func NewMITMConfig(ca *x509.Certificate, caPrivKey crypto.PrivateKey, optFns ...func(*MITMOptions)) (*MITMConfig, error) {
	options := MITMOptions{
		CertStorage:  NewMapCertStorage(),
		Organization: "mitmproxy",
		Validity:     time.Hour,
		Logger:       golog.NewGoLogger(golog.INFO, log.Default()),
	}

	for _, fn := range optFns {
		fn(&options)
	}

	if options.CertTemplateGen == nil {
		options.CertTemplateGen = func(serial *big.Int, ski []byte, hostname, organization string, validity time.Duration) *x509.Certificate {
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject: pkix.Name{
					CommonName:   hostname,
					Organization: []string{organization},
				},
				SubjectKeyId:          ski,
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				NotBefore:             time.Now().Add(-validity),
				NotAfter:              time.Now().Add(validity),
			}

			if ip := net.ParseIP(hostname); ip != nil {
				tmpl.IPAddresses = []net.IP{ip}
			} else {
				tmpl.DNSNames = []string{hostname}
			}

			return tmpl
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// Generating the private key that will be used for domain certificates
	priv, err := generateKey(caPrivKey)
	if err != nil {
		return nil, err
	}

	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	// nolint: gosec // ok
	h := sha1.New()

	_, err = h.Write(pkixpub)
	if err != nil {
		return nil, err
	}

	keyID := h.Sum(nil)

	return &MITMConfig{
		ca:              ca,
		caPrivateKey:    caPrivKey,
		privateKey:      priv,
		keyID:           keyID,
		validity:        options.Validity,
		organization:    options.Organization,
		certStorage:     options.CertStorage,
		certTemplateGen: options.CertTemplateGen,
		logger:          options.Logger,
		roots:           roots,
	}, nil
}

// GetCA returns the authority cert
func (c *MITMConfig) CA() *x509.Certificate {
	return c.ca
}

// NewTLSConfigForHost creates a *tls.Config that will generate
// domain certificates on-the-fly using the SNI extension (if specified)
// or the hostname
func (c *MITMConfig) NewTLSConfigForHost(hostname string) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.GetOrCreateCert(host)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}

	// Accept client certs without verifying them
	// Note that we will still verify remote server certs
	tlsConfig.InsecureSkipVerify = true

	return tlsConfig
}

// GetOrCreateCert gets or creates a certificate for the specified hostname
func (c *MITMConfig) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	if tlsCertificate, ok := c.certStorage.Get(hostname); ok {
		c.logDebugf("Cache hit for %s", hostname)

		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err = tlsCertificate.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsCertificate, nil
		}

		c.logDebugf("Invalid certificate in the cache for %s", hostname)
	}

	c.logDebugf("Cache miss for %s", hostname)

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, err
	}

	tmpl := c.certTemplateGen(serial, c.keyID, hostname, c.organization, c.validity)

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.privateKey.Public(), c.caPrivateKey)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsCertificate := &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        x509c,
	}

	c.certStorage.Add(hostname, tlsCertificate)

	return tlsCertificate, nil
}

func (c *MITMConfig) logf(level golog.Level, format string, args ...interface{}) {
	c.logger.Printf(level, format, args...)
}

func (c *MITMConfig) logDebugf(format string, args ...interface{}) {
	c.logf(golog.DEBUG, format, args...)
}

func generateKey(privateKey crypto.PrivateKey) (crypto.Signer, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.GenerateKey(rand.Reader, 2048)
	case *ecdsa.PrivateKey:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type %T", privateKey)
	}
}
