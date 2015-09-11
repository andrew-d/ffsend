package ptls

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/andrew-d/id"
)

var _ = fmt.Println

func TestUsage(t *testing.T) {
	certPem := []byte(strings.TrimSpace(cert))
	keyPem := []byte(strings.TrimSpace(key))

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("could not parse certificate / key: %s", err)
	}

	certID := IDFromTLSCert(cert)
	fmt.Println("cert ID:", certID)

	var (
		wg             sync.WaitGroup
		server, client = net.Pipe()
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer server.Close()

		// Start the ptls connection
		_, err := Server(server, cert, []id.ID{certID})
		if err != nil {
			t.Errorf("error authenticating to client: %s", err)
			return
		}

		// Done!
		fmt.Println("server connected successfully")
	}()

	go func() {
		defer wg.Done()
		defer client.Close()

		// Start the ptls connection
		_, err := Client(client, cert, []id.ID{certID})
		if err != nil {
			t.Errorf("error authenticating to server: %s", err)
			return
		}

		// Done!
		fmt.Println("client connected successfully")
	}()

	wg.Wait()
	fmt.Println("test finished")
}

const cert = `
-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIQbaYt821fqbYbwMbg03YR5TANBgkqhkiG9w0BAQsFADA3
MQ8wDQYDVQQKEwZmZnNlbmQxJDAiBgNVBAMTG0FuZHJld3MtTWFjQm9vay1Qcm8t
Mi5sb2NhbDAeFw0xNTA5MDQwMTQyMjRaFw0xNjA5MDMwMTQyMjRaMDcxDzANBgNV
BAoTBmZmc2VuZDEkMCIGA1UEAxMbQW5kcmV3cy1NYWNCb29rLVByby0yLmxvY2Fs
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArfZ3i21w1xPeB5rDUBch
iTSJyH+//vApApOZJBwZEsLJ772bg/FAKXOyWV7ibno/PY3xhgAcfFlMoRlfewKc
/P0J5Ny0lY+vTCsbXOeoAIQ/77jUTu1UYpdyuqnxVXuxSweLI0MCdv8PIeKnvNRH
6tJquZCF5Ax9dS6WP0y3Fxy1lc0mVXNtIdKoGNJLzSrT3SwPZ68z7aFlGlDBOZWd
g38prZbgkqWf8d4dkAuF6uQMZO/1L5k+n0Myhk/JLWHa/IXGUQRkvene1iTxmLwB
Wxm/tJe0jnTn/IVxWmaN0iGPQXjTD2XecuKwiYIC5GPOfheVO1adq1mWpiCvpGew
rwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFXa
mJccJgESjgCUIM6YoXah6jLB5H/DdJcOX84TqvozaYGTsVDV6WvZSZXK+HoRizaj
l/K7/2m4jHsUOS6InPS+Wpe3Y5j5yNlHNZ8zb+/iJEvgbny+6jq79PKittjsfjDZ
yWoSiPPbKikPo/GcqZYd4AeHiOYO0tgH4uS8L4HkK+iJQW8pTPL4avIqdmvASM1D
o3ttqr++oCUVLR0MonhMc1jxcU53D+UA01OnsBI0/TH6jQs7oOLT92iuWiHDD80q
B7kW3cPDotk6cf0vx6d/T/Ra9h2NP/cryKmgmLMCe/pI4RdGufENtGCK/Ug6KUnb
k9G7Ko2enRygs8p/FTY=
-----END CERTIFICATE-----
`

const key = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArfZ3i21w1xPeB5rDUBchiTSJyH+//vApApOZJBwZEsLJ772b
g/FAKXOyWV7ibno/PY3xhgAcfFlMoRlfewKc/P0J5Ny0lY+vTCsbXOeoAIQ/77jU
Tu1UYpdyuqnxVXuxSweLI0MCdv8PIeKnvNRH6tJquZCF5Ax9dS6WP0y3Fxy1lc0m
VXNtIdKoGNJLzSrT3SwPZ68z7aFlGlDBOZWdg38prZbgkqWf8d4dkAuF6uQMZO/1
L5k+n0Myhk/JLWHa/IXGUQRkvene1iTxmLwBWxm/tJe0jnTn/IVxWmaN0iGPQXjT
D2XecuKwiYIC5GPOfheVO1adq1mWpiCvpGewrwIDAQABAoIBAQCYGoYP3NLq2y4p
DAJ2BqOF6fAG5NwktivFWvRthDvQEYyrF+fgB5KIK+bnCXWGD1E4KuHgvjwp5ZKA
0USQs4o8EasS9n7WvlkRiidUpiBYw0l7+ul3UT+VLMJdv7WJfqtX5PKdFDwVe5Hp
mNn82sc+5Ff4hArtiJYxXVh1ZEg55ahye8eGEKEN5tyxg0loOiDZPrNniJP+ytT+
cPxJebX4u//zxt1zgBrNVAqOxcBGLeaJkwY+NwQmm/30UElfo+A/SAAxouGfa8QU
geYYNFyvSFHZaAtPGfn6/KAjcB+w89t4OLCSWi70YErKaUuEMyB93sGUFI2Ujrkq
Rp8VhUdBAoGBAMWb3NCs06FVnNftToN+WO2DfZTm4fRME5UOnL3NjSZ5BJT7z//j
qzMIXhDRic+UsW13IAJgw5tCKQgZECTemweDRwLsnjhljEBkLMa+V+OO0L8Yg06f
cdEsocoHhIkLlkST36d0QgmqORtDW7pnOdc8s0bDDvg5HPTjLgaNxiU/AoGBAOFd
5Rpm1ZJQ01h0o81Clv6lz42tRZtO5Dmingwvb2QdR0gBXgJ5d8HHxnoUXOLOnZIp
u683miDuN39IPP+ZHsQXUvoRWfHBmzFq7bp+WTGXQnvO68Ra1dY70qCPQZxEAQuz
/Hi/RSvTxat+FT6FA9h16CfSXPVCN9pTRNJeNWiRAoGBAISRQZwEtZ0gUC5Tlz6D
vqjoc5E3KxK3DtQKj4CNq0nKGhbQsAOc+rcrv99Mk0VdHYKwThsKS2+W/Ovf1ILH
i/2IRlVh4+s1xNdV3OwfudqBbu0kRsKyGKsZZBii3nkJ+u9avMocJklRlyoBEEKH
CbipkiPArAQ+XHy1A6WF6w4FAoGBAJ+OOYjSq3xWqvriQaIt9fc9709QEIrfdOd1
QU5BOyz3KaNKDIPV+bqBNPzzc7vEKnzz/QQVapLL9RCxVTZk8wpDtSSEqlhmCPkY
ykyR7ZYVkCVVn0g6Q1DUs8+m/P2ki9T8TdAzIsbfvQAoWOQVil5zQ7UF03h0tFRn
Rb9moYtxAoGALZuWTkFVXqRDPXCLeYBLXJ8gNj6dxicFA29+/oRmqXyMtrlbIIDS
Jm0A2AfLem69nEt7qncC+aa0nv0LGNntkK96TNUOk1xiNeMd9H0SZg/K3ykA1qAP
rYelGhd6fAmyBOTV+JBNaRULuHd9ztpkqkbZnjlO6cmWHiX3KFUjLRs=
-----END RSA PRIVATE KEY-----
`
