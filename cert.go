package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
)

func certGenerateCSRandKey() error {
	log.Printf("Generating CSR and key...\n")

	keys, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("unable to genarate private keys, error: %s", err)
	}

	subject := pkix.Name{
		Country:            []string{"USA"},
		Province:           []string{"UT"},
		Locality:           []string{"Salt Lake City"},
		Organization:       []string{"Test"},
		OrganizationalUnit: []string{"Test"},
		CommonName:         "dig.wtf"}

	template := x509.CertificateRequest{Subject: subject}

	csrBinary, err := x509.CreateCertificateRequest(rand.Reader, &template, keys)
	if err != nil {
		return fmt.Errorf("unable to genarate csr, error: %s", err)
	}

	csrPem := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBinary,
	})

	log.Printf("CSR:\n%s\n", string(csrPem))

	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keys)})

	log.Printf("KEY:\n%s\n", string(privateKey))

	return nil
}
