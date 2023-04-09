package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(log.Lshortfile)

	testCmd := flag.NewFlagSet("test", flag.ExitOnError)
	testHost := testCmd.String("host", "127.0.0.1", "Host")
	testPort := testCmd.String("port", "443", "Port")
	testName := testCmd.String("name", "", "Server name to validate certificate with.")
	testVerify := testCmd.Bool("verify", false, "Verify certificate.")

	if len(os.Args) < 2 {
		fmt.Println("Usage: tlsTest test -host <hostname or ip>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "test":
		testCmd.Parse(os.Args[2:])
		if *testVerify {
			*testVerify = false
		}

		tlsConn := NewTLSConn()

		tlsConn.SetHost(*testHost)
		tlsConn.SetPort(*testPort)
		tlsConn.SetName(*testName)
		tlsConn.SetVerify(*testVerify)

		err := tlsConn.Dial()
		if err != nil {
			log.Print(err)
		}

		tlsConn.PrintConnectionStatus()
	default:
		fmt.Println("Usage: tlsTest test -host <hostname or ip>")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
