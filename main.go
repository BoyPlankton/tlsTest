package main

import (
	"flag"
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

	tlsConn := NewTLSConn()

	tlsConn.SetHost(*host)
	tlsConn.SetPort(*port)
	tlsConn.SetName(*name)
	tlsConn.SetVerify(*verify)

	err := tlsConn.Dial()
	if err != nil {
		log.Print(err)
	}

	tlsConn.PrintConnectionStatus()
}
