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

func returnTLSVersion(version uint16) string {
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

func returnTLSCurve(curve tls.CurveID) string {
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

func testTLSConfig(host string, port string, name string, verify bool, tlsVersion uint16, cipherSuite uint16) bool {
	tmpCS := []uint16{cipherSuite}

	conf := &tls.Config{
		InsecureSkipVerify: verify,
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
		CipherSuites:       tmpCS,
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

// TLSConn is a struct for holding all the details
// of a TLS connection.
type TLSConn struct {
	host   string
	port   string
	name   string
	verify bool

	conf *tls.Config

	conn *tls.Conn

	tlsVersions []uint16

	tlsCurves []tls.CurveID
}

// NewTLSConn creates a new TLS connection.
func NewTLSConn() TLSConn {
	c := TLSConn{}

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

// Dial opens a TLS connection
func (c *TLSConn) Dial() error {
	conn, err := tls.Dial("tcp", c.host+":"+c.port, c.conf)
	if err != nil {
		return err
	}

	c.conn = conn

	return nil
}

// SetHost sets the host
func (c *TLSConn) SetHost(host string) {
	c.host = host
}

// SetPort sets the port
func (c *TLSConn) SetPort(port string) {
	c.port = port
}

// SetName sets the name
func (c *TLSConn) SetName(name string) {
	c.name = name
}

// SetVerify sets the verify flag
func (c *TLSConn) SetVerify(verify bool) {
	c.conf.InsecureSkipVerify = verify
}

// PrintConnectionStatus prints the connection status
func (c *TLSConn) PrintConnectionStatus() {
	tlsVersions := [...]uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
	}

	cipherSuites := [...]uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_FALLBACK_SCSV,
	}

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
	PrintDetails("Version", TLSVersionName(cs.Version))
	PrintDetails("Cipher Suite", CipherSuiteName(cs.CipherSuite))

	fmt.Printf("\nSupported TLS/SSL Versions\n")
	fmt.Println(strings.Repeat("*", 80))

	fmt.Printf("%-40s", "Cipher Suite")

	for _, tlsVersion := range tlsVersions {
		fmt.Printf(" %-7s", TLSVersionName(tlsVersion))
	}

	fmt.Printf("\n")

	fmt.Println(strings.Repeat("*", 80))

	for _, cipherSuite := range cipherSuites {
		fmt.Printf("%-40s", CipherSuiteName(cipherSuite))

		for _, tlsVersion := range tlsVersions {
			fmt.Printf(" %-7v", testTLSConfig(c.host, c.port, c.name, c.verify, tlsVersion, cipherSuite))
		}

		fmt.Printf("\n")
	}
}

// PrintDetails prints the details
func PrintDetails(title string, data string) {
	fmt.Printf("%-23s: %s\n", title, data)
}

// PublicKeyDetails returns the public key details
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

// CipherSuiteName returns the name of the Cipher Suite
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

// TLSVersionName returns the name of the TLS version
func TLSVersionName(version uint16) string {
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
