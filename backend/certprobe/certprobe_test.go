package certprobe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestWeakSignatureAlgorithm(t *testing.T) {
	weak := []x509.SignatureAlgorithm{
		x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
	}
	for _, alg := range weak {
		if !weakSignatureAlgorithm(alg) {
			t.Errorf("%v: expected weak", alg)
		}
	}
	strong := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.PureEd25519,
		x509.SHA256WithRSAPSS,
	}
	for _, alg := range strong {
		if weakSignatureAlgorithm(alg) {
			t.Errorf("%v: unexpectedly flagged weak", alg)
		}
	}
}

func TestPublicKeyInfo(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		pub      any
		wantType string
		wantBits int
	}{
		{"RSA 1024", &rsa1024.PublicKey, "RSA", 1024},
		{"RSA 2048", &rsa2048.PublicKey, "RSA", 2048},
		{"ECDSA P-256", &ecKey.PublicKey, "ECDSA", 256},
		{"Ed25519", edPub, "Ed25519", 256},
		{"unrecognized", "bogus", "", 0},
	}
	for _, c := range cases {
		gotType, gotBits := publicKeyInfo(c.pub)
		if gotType != c.wantType || gotBits != c.wantBits {
			t.Errorf("%s: got (%q, %d), want (%q, %d)", c.name, gotType, gotBits, c.wantType, c.wantBits)
		}
	}
}
