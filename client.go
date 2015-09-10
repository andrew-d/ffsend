package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"

	"github.com/andrew-d/id"
	"github.com/andrew-d/ptls"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "connect to a server in order to retrieve a file",
	Run:   runClient,
}

func runClient(cmd *cobra.Command, args []string) {
	if !haveCertAndKey() {
		log.Fatalln("do not have a certificate / key - please run `ffsend generate` first!")
	}

	certPem, keyPem, err := loadCertAndKey()
	if err != nil {
		log.Fatalf("could not load certificate / key: %s", err)
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatalf("could not parse certificate / key: %s", err)
	}
	certID := ptls.IDFromTLSCert(cert)

	serverAddr := ":12345"
	log.Printf("connecting to server on: %s", serverAddr)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("could not dial server: %s", err)
	}

	log.Printf("authenticating to server")
	conn, err = ptls.Client(conn, cert, []id.ID{certID})
	if err != nil {
		log.Fatalf("error authenticating with server: %s", err)
	}

	io.WriteString(conn, "test 1234")
}
