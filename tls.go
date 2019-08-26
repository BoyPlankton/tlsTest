package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

func returnTlsVersion(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}

	return "Unknown"
}

func returnTlsCurve(curve tls.CurveID) string {
	switch curve {
	case tls.CurveP256:
		return "P256"
	case tls.CurveP384:
		return "P384"
	case tls.CurveP521:
		return "P521"
	case tls.X25519:
		return "X25519"
	}

	return "Unknown"
}

func testTlsConfig(host string, port string, name string, verify bool, tlsVersion uint16) bool {
	conf := &tls.Config{
		InsecureSkipVerify: verify,
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
	}

	if len(name) > 0 {
		conf.ServerName = name
	}

	conn, err := tls.Dial("tcp", host+":"+port, conf)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

type TlsConn struct {
	host   string
	port   string
	name   string
	verify bool

	conf *tls.Config

	conn *tls.Conn

	tlsVersions []uint16

	tlsCurves []tls.CurveID
}

func NewTlsConn() TlsConn {
	c := TlsConn{}

	c.tlsVersions = []uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
	}

	c.tlsCurves = []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.X25519,
	}

	c.conf = &tls.Config{}

	return c
}

func (c *TlsConn) Dial() error {
	conn, err := tls.Dial("tcp", c.host+":"+c.port, c.conf)
	if err != nil {
		return err
	}

	c.conn = conn

	return nil
}

func (c *TlsConn) SetHost(host string) {
	c.host = host
}

func (c *TlsConn) SetPort(port string) {
	c.port = port
}

func (c *TlsConn) SetVerify(verify bool) {
	c.conf.InsecureSkipVerify = verify
}

func (c *TlsConn) PrintConnectionStatus() {
	cs := c.conn.ConnectionState()

	for i, cert := range cs.PeerCertificates {
		if i > 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("Server Key and Certificate #%d\n", i+1)
		fmt.Println(strings.Repeat("*", 80))

		PrintDetails("Subject", cert.Subject.String())
		PrintDetails("Alternative Names", strings.Join(cert.DNSNames, ","))
		PrintDetails("Serial Number", cert.SerialNumber.Text(16))
		PrintDetails("Valid From", cert.NotBefore.Format(time.RFC1123))
		PrintDetails("Valid Until", fmt.Sprintf("%s (expires in %d days)",
			cert.NotAfter.Format(time.RFC1123),
			int(cert.NotAfter.Sub(time.Now()).Hours()/24)))

		PrintDetails("Key", PublicKeyDetails(cert))

		//weak key

		PrintDetails("Issuer", cert.Issuer.String())
		PrintDetails("Signature Algorithm", cert.SignatureAlgorithm.String())

		//extended validation
		// I can't find any examples of extended validation.

		//certificate transparency
		//OCSP must staple
		//revocation information
		PrintDetails("Revocation Information", strings.Join(cert.CRLDistributionPoints, ","))

		//revocation status
		//DNS CAA
		//Trusted
	}

	fmt.Printf("\nDefault Connection Details\n")
	fmt.Println(strings.Repeat("*", 80))
	PrintDetails("Version", TlsVersionName(cs.Version))
	PrintDetails("Cipher Suite", CipherSuiteName(cs.CipherSuite))
}

func PrintDetails(title string, data string) {
	fmt.Printf("%-23s: %s\n", title, data)
}

func PublicKeyDetails(cert *x509.Certificate) string {
	var retString = "Unsupported Key"

	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		retString = fmt.Sprintf("%s %d bits (e %d)", cert.PublicKeyAlgorithm.String(),
			pubKey.N.BitLen(),
			pubKey.E)
	case *ecdsa.PublicKey:
		retString = fmt.Sprintf("%s %d bits", cert.PublicKeyAlgorithm.String(),
			pubKey.Curve.Params().BitSize)
	}

	return retString
}

func CipherSuiteName(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"
	}

	return "Unknown"
}

func TlsVersionName(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}

	return "Unknown"
}
