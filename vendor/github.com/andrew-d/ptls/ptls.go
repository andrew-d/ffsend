package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/andrew-d/id"
)

// Server creates a TLS server-side connection using conn as the underlying
// transport.  You must provide a TLS certificate to present to clients, along
// with an array of valid certificate IDs that are allowed to connect.
//
// A default TLS configuration will be used with sensible defaults.
func Server(conn net.Conn, cert tls.Certificate, clientIDs []id.ID) (net.Conn, error) {
	config := makeConfig(cert)
	srv := tls.Server(conn, config)
	if err := validatePeerID(srv, clientIDs); err != nil {
		srv.Close()
		return nil, err
	}

	return srv, nil
}

// Client creates a TLS client-side connection using conn as the underlying
// transport.  You must provide a TLS certificate to present to the server,
// along with an array of valid certificate IDs that the server may present.
//
// A default TLS configuration will be used with sensible defaults.
func Client(conn net.Conn, cert tls.Certificate, serverIDs []id.ID) (net.Conn, error) {
	config := makeConfig(cert)
	c := tls.Client(conn, config)
	if err := validatePeerID(c, serverIDs); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

// IDFromTLSCert will return the ID for the given TLS certificate.  If this
// function is passed an invalid TLS certificate, it will panic.
func IDFromTLSCert(cert tls.Certificate) id.ID {
	// Get the x509 cert for the given TLS certificate.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}

	return IDFromX509Cert(x509Cert)
}

// IDFromTLSCert will return the ID for the given x509 certificate.
func IDFromX509Cert(cert *x509.Certificate) id.ID {
	return id.New(cert.Raw)
}

func makeConfig(cert tls.Certificate) *tls.Config {
	config := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequestClientCert,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
	}
	return config
}

func validatePeerID(conn *tls.Conn, validIDs []id.ID) error {
	// Try a TLS connection over the given connection.  We explicitly perform
	// the handshake, since we want to maintain the invariant that, if this
	// function returns successfully, then the connection should be valid and
	// verified.
	if err := conn.Handshake(); err != nil {
		return err
	}

	cs := conn.ConnectionState()

	// We should have exactly one peer certificate.
	certs := cs.PeerCertificates
	if cl := len(certs); cl != 1 {
		return ImproperCertsNumberError{cl}
	}

	// Get remote cert's ID.
	remoteCert := certs[0]
	remoteID := id.New(remoteCert.Raw)

	// The cert should match one of our valid IDs.
	// NOTE: use .Equals here to prevent timing attacks (not `==`)
	valid := false
	for _, id := range validIDs {
		if id.Equals(remoteID) {
			valid = true
			break
		}
	}

	if !valid {
		return InvalidPeerCertError{remoteCert}
	}

	return nil
}

// ImproperCertsNumberError is returned from Server/Client whenever the remote
// peer presents a number of PeerCertificates that is not 1.
type ImproperCertsNumberError struct {
	n int
}

func (e ImproperCertsNumberError) Error() string {
	return fmt.Sprintf("ptls: expecting 1 peer certificate, got %d", e.n)
}

// InvalidPeerCertError is returned from Server/Client whenever the remote peer
// presents a certificate with an unknown ID.
type InvalidPeerCertError struct {
	cert *x509.Certificate
}

func (e InvalidPeerCertError) Error() string {
	return "ptls: peer did not present a valid certificate"
}

// Returns the (invalid) ID presented by the remote peer.
func (e InvalidPeerCertError) CertificateID() id.ID {
	return id.New(e.cert.Raw)
}

// Returns the (invalid) certificate presented by the remote peer.
func (e InvalidPeerCertError) Certificate() *x509.Certificate {
	return e.cert
}
