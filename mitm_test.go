package mitmproxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMITM(t *testing.T) {
	ca, privateKey, err := NewCA("mitmproxy ca", "mitmproxy", 24*time.Hour)
	assert.NoError(t, err)
	assert.NotNil(t, ca)
	assert.NotNil(t, privateKey)

	c, err := NewMITMConfig(ca, privateKey, func(m *MITMOptions) {
		m.Validity = 20 * time.Hour
		m.Organization = "Test Organization"
	})
	assert.NoError(t, err)

	conf := c.NewTLSConfigForHost("example.org")
	assert.Equal(t, []string{"http/1.1"}, conf.NextProtos)
	assert.True(t, conf.InsecureSkipVerify)

	// Test generating a certificate
	clientHello := &tls.ClientHelloInfo{
		ServerName: "example.org",
	}
	tlsCert, err := conf.GetCertificate(clientHello)
	assert.NoError(t, err)
	assert.NotNil(t, tlsCert)

	// Assert certificate details
	x509c := tlsCert.Leaf
	assert.Equal(t, "example.org", x509c.Subject.CommonName)
	assert.Nil(t, x509c.VerifyHostname("example.org"))
	assert.Equal(t, []string{"Test Organization"}, x509c.Subject.Organization)
	assert.NotNil(t, x509c.SubjectKeyId)
	assert.True(t, x509c.BasicConstraintsValid)
	assert.True(t, x509c.KeyUsage&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment)
	assert.True(t, x509c.KeyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509c.ExtKeyUsage)
	assert.Equal(t, []string{"example.org"}, x509c.DNSNames)
	assert.True(t, x509c.NotBefore.Before(time.Now().Add(-2*time.Hour)))
	assert.True(t, x509c.NotAfter.After(time.Now().Add(2*time.Hour)))

	// Check that certificate is cached
	tlsCert2, err := c.GetOrCreateCert("example.org")
	assert.Nil(t, err)
	assert.True(t, tlsCert == tlsCert2)

	// Check the certificate for an IP
	tlsCertForIP, err := c.GetOrCreateCert("192.168.0.1:443")
	assert.NoError(t, err)

	x509c = tlsCertForIP.Leaf
	assert.Equal(t, 1, len(x509c.IPAddresses))
	assert.True(t, net.ParseIP("192.168.0.1").Equal(x509c.IPAddresses[0]))
}
