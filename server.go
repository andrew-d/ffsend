package main

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/andrew-d/id"
	"github.com/andrew-d/ptls"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "start a server that will send a file to connected clients",
	Run:   runServer,
}

func runServer(cmd *cobra.Command, args []string) {
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

	listenAddr := ":12345"
	log.Printf("starting server on: %s", listenAddr)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Could not start TCP listener: %s", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error accepting TCP connection: %s", err)
			break
		}

		log.Printf("accepted connection from %s to %s", conn.RemoteAddr(), listenAddr)
		go handleClient(conn, cert, certID)
	}
}

func handleClient(tcpConn net.Conn, ourCert tls.Certificate, ourID id.ID) {
	conn, err := ptls.Server(tcpConn, ourCert, []id.ID{ourID})
	if err != nil {
		log.Printf("error authenticating with client: %s", err)
		tcpConn.Close()
		return
	}
	defer conn.Close()

	time.Sleep(1 * time.Second)
	log.Printf("finished")
}
