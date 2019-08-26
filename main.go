package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)

	host := flag.String("host", "127.0.0.1", "Host")
	port := flag.String("port", "443", "Port")
	name := flag.String("name", "", "Server name to validate certificate with.")
	verify := flag.Bool("verify", false, "Verify certificate.")

	flag.Parse()

	if *verify == true {
		*verify = false
	} else {
		*verify = true
	}

	log.Printf("Host: %v, Port: %v, Verify: %v\n", *host, *port, *verify)

	tlsConn := NewTlsConn()

	tlsConn.SetHost(*host)
	tlsConn.SetPort(*port)
	tlsConn.SetVerify(*verify)

	err := tlsConn.Dial()
	if err != nil {
		log.Print(err)
	}

	tlsConn.PrintConnectionStatus()

	tlsVersions := [...]uint16{
		tls.VersionSSL30,
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
	}

	/*
		tlsCurves := [...]tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		}
	*/

	//for tlsVersion := range tlsVersions {
	for i := 0; i < len(tlsVersions); i++ {
		//for j := 0; j < len(tlsCurves); j++ {
		fmt.Printf("\t%v\tStatus:%v\n", returnTlsVersion(tlsVersions[i]), testTlsConfig(*host, *port, *name, *verify, tlsVersions[i]))
		//}
	}
}
