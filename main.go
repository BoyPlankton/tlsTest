package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(log.Lshortfile)

	if len(os.Args) < 2 {
		fmt.Println("Usage: tlsTest test <hostname or ip>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "test":
		testCmd := flag.NewFlagSet("test", flag.ExitOnError)
		testPort := testCmd.String("port", "443", "Port")
		testName := testCmd.String("name", "", "Server name to validate certificate with.")
		testVerify := testCmd.Bool("verify", false, "Verify certificate.")

		if len(os.Args) < 3 {
			fmt.Println("Usage: tlsTest test <hostname or ip> [-port <port>] [-name <server name>] [-verify]")
			flag.PrintDefaults()
			os.Exit(1)
		}

		err := testCmd.Parse(os.Args[3:])
		if err != nil {
			log.Print(err)
		}

		log.Print(*testPort)

		testHost := os.Args[2]

		if *testVerify {
			*testVerify = false
		}

		tlsConn := NewTLSConn()

		tlsConn.SetHost(testHost)
		tlsConn.SetPort(*testPort)
		tlsConn.SetName(*testName)
		tlsConn.SetVerify(*testVerify)

		err = tlsConn.Dial()
		if err != nil {
			// TODO: Handle no such host error
			log.Print(err)
		}

		tlsConn.PrintConnectionStatus()
	case "cert":
		switch os.Args[2] {
		case "gen":
			err := certGenerateCSRandKey()
			if err != nil {
				log.Print(err)
			}
		default:
			fmt.Println("Usage: tlsTest cert gen <common name>")
			os.Exit(1)
		}
	default:
		fmt.Println("Usage: tlsTest test -host <hostname or ip>")
		flag.PrintDefaults()
		os.Exit(1)
	}
}
