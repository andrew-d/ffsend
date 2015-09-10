package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "generate a client-local TLS key to use for authentication",
	Run:   runGenerate,
}

var (
	flagGenerateForce bool
)

func init() {
	generateCmd.Flags().BoolVarP(&flagGenerateForce, "force", "f", false,
		"overwrite an existing certificate")
}

func runGenerate(cmd *cobra.Command, args []string) {
	if haveCertAndKey() && !flagGenerateForce {
		log.Println("have existing certificate and key and --force was not given")
		return
	}

	cert, key, err := generateCertificate()
	if err != nil {
		log.Printf("could not generate certificate and key: %s", err)
		os.Exit(1)
	}

	err = saveCertAndKey(cert, key)
	if err != nil {
		log.Printf("could not save certificate and key: %s", err)
		os.Exit(1)
	}

	log.Println("successfully generated certificate and key")
}

func getKCPaths() (certPath, keyPath string) {
	rootPath := os.ExpandEnv(filepath.Join("$HOME", ".ffsend"))

	certPath = filepath.Join(rootPath, "cert.pem")
	keyPath = filepath.Join(rootPath, "key.pem")
	return
}

func haveCertAndKey() bool {
	certPath, keyPath := getKCPaths()

	for _, path := range []string{certPath, keyPath} {
		st, err := os.Stat(path)
		if err != nil {
			return false
		}

		if !st.Mode().IsRegular() {
			return false
		}
	}

	return true
}

func loadCertAndKey() (cert []byte, key []byte, err error) {
	certPath, keyPath := getKCPaths()

	cert, err = ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	key, err = ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func saveCertAndKey(cert, key []byte) error {
	certPath, keyPath := getKCPaths()

	// Write to files.
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}

	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)

	if err := ioutil.WriteFile(certPath, cert, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(keyPath, key, 0600); err != nil {
		return err
	}

	return nil
}

// Generates a new self-signed private/public key and returns (cert, key, error).
func generateCertificate() ([]byte, []byte, error) {
	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"ffsend"},
		},
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,

		IsCA: true,
	}

	// Set the common name to our hostname.
	host, err := os.Hostname()
	if err != nil {
		return nil, nil, err
	}
	template.Subject.CommonName = host
	// TODO: maybe append to IPAddresses / DNSNames with interfaces?

	// We expire after a year.
	template.NotAfter = template.NotBefore.Add(time.Hour * 24 * 365)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	template.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Great, all success!
	var certBuf, keyBuf bytes.Buffer
	if err = pem.Encode(
		&certBuf,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	); err != nil {
		return nil, nil, err
	}

	if err = pem.Encode(
		&keyBuf,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	); err != nil {
		return nil, nil, err
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
