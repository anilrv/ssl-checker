package certprobe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// testPKI is a throwaway CA plus a leaf it issued — everything the revocation paths
// need, generated in-memory so no network or fixture files are involved.
type testPKI struct {
	ca      *x509.Certificate
	caKey   *rsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *rsa.PrivateKey
}

// newTestPKI issues a leaf whose OCSPServer / CRLDistributionPoints are set to the
// given URLs (either may be nil).
func newTestPKI(t *testing.T, ocspURLs, crlURLs []string) *testPKI {
	t.Helper()
	now := time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Revocation CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlURLs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return &testPKI{ca: ca, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

func (p *testPKI) ocspResponse(t *testing.T, status int) []byte {
	t.Helper()
	now := time.Now()
	template := ocsp.Response{
		Status:       status,
		SerialNumber: p.leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   now.Add(time.Hour),
	}
	if status == ocsp.Revoked {
		template.RevokedAt = now.Add(-time.Minute)
		template.RevocationReason = ocsp.KeyCompromise
	}
	der, err := ocsp.CreateResponse(p.ca, p.ca, template, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (p *testPKI) crl(t *testing.T, revokedSerials ...*big.Int) []byte {
	t.Helper()
	now := time.Now()
	var entries []x509.RevocationListEntry
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: now.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, p.ca, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// allowLoopback bypasses ssrfguard for the duration of one test so httptest servers on
// 127.0.0.1 (which the guard rightly refuses in production) can stand in for real
// OCSP responders and CRL distribution points.
func allowLoopback(t *testing.T) {
	t.Helper()
	orig := resolvePublicIP
	resolvePublicIP = func(ctx context.Context, hostname string) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}
	t.Cleanup(func() { resolvePublicIP = orig })
}

func TestCheckRevocationRequiresIssuer(t *testing.T) {
	pki := newTestPKI(t, nil, nil)
	r := &Result{Leaf: pki.leaf} // no Issuer
	CheckRevocation(context.Background(), r)
	if r.RevocationStatus != "" || r.RevocationSource != "" {
		t.Errorf("expected no verdict without issuer, got %q/%q", r.RevocationStatus, r.RevocationSource)
	}
}

func TestCheckRevocationStapled(t *testing.T) {
	cases := []struct {
		name       string
		ocspStatus int
		want       string
	}{
		{"stapled revoked", ocsp.Revoked, RevocationRevoked},
		{"stapled good", ocsp.Good, RevocationGood},
	}
	for _, c := range cases {
		pki := newTestPKI(t, nil, nil)
		r := &Result{Leaf: pki.leaf, Issuer: pki.ca, RawOCSPStaple: pki.ocspResponse(t, c.ocspStatus)}
		CheckRevocation(context.Background(), r)
		if r.RevocationStatus != c.want || r.RevocationSource != "stapled-ocsp" {
			t.Errorf("%s: got %q/%q, want %q/stapled-ocsp", c.name, r.RevocationStatus, r.RevocationSource, c.want)
		}
	}
}

func TestCheckRevocationActiveOCSP(t *testing.T) {
	allowLoopback(t)

	for _, c := range []struct {
		name       string
		ocspStatus int
		want       string
	}{
		{"responder says revoked", ocsp.Revoked, RevocationRevoked},
		{"responder says good", ocsp.Good, RevocationGood},
	} {
		// The response must be built for THIS pki's leaf, but the pki needs the server
		// URL first — so capture via closure and start the server before issuing.
		var pki *testPKI
		var status = c.ocspStatus
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/ocsp-request" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.ReadAll(req.Body)
			_, _ = w.Write(pki.ocspResponse(t, status))
		}))
		defer srv.Close()

		pki = newTestPKI(t, []string{srv.URL}, nil)
		r := &Result{Leaf: pki.leaf, Issuer: pki.ca}
		CheckRevocation(context.Background(), r)
		if r.RevocationStatus != c.want || r.RevocationSource != "ocsp" {
			t.Errorf("%s: got %q/%q, want %q/ocsp", c.name, r.RevocationStatus, r.RevocationSource, c.want)
		}
	}
}

func TestCheckRevocationCRL(t *testing.T) {
	allowLoopback(t)

	// Revoked: the CRL lists the leaf's serial.
	{
		var pki *testPKI
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write(pki.crl(t, big.NewInt(4242)))
		}))
		defer srv.Close()
		pki = newTestPKI(t, nil, []string{srv.URL})
		r := &Result{Leaf: pki.leaf, Issuer: pki.ca}
		CheckRevocation(context.Background(), r)
		if r.RevocationStatus != RevocationRevoked || r.RevocationSource != "crl" {
			t.Errorf("listed serial: got %q/%q, want revoked/crl", r.RevocationStatus, r.RevocationSource)
		}
	}

	// Good: a validated, current CRL that does NOT list the serial is definitive.
	{
		var pki *testPKI
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write(pki.crl(t, big.NewInt(999)))
		}))
		defer srv.Close()
		pki = newTestPKI(t, nil, []string{srv.URL})
		r := &Result{Leaf: pki.leaf, Issuer: pki.ca}
		CheckRevocation(context.Background(), r)
		if r.RevocationStatus != RevocationGood || r.RevocationSource != "crl" {
			t.Errorf("unlisted serial: got %q/%q, want good/crl", r.RevocationStatus, r.RevocationSource)
		}
	}

	// A CRL signed by the wrong CA must be rejected — no verdict at all.
	{
		imposter := newTestPKI(t, nil, nil)
		var pki *testPKI
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write(imposter.crl(t, big.NewInt(4242)))
		}))
		defer srv.Close()
		pki = newTestPKI(t, nil, []string{srv.URL})
		r := &Result{Leaf: pki.leaf, Issuer: pki.ca}
		CheckRevocation(context.Background(), r)
		if r.RevocationStatus != "" {
			t.Errorf("imposter CRL: got %q, want no verdict", r.RevocationStatus)
		}
	}
}

func TestGuardedFetchRefusesPrivateTargets(t *testing.T) {
	// No resolvePublicIP override here: the real ssrfguard must refuse loopback,
	// so a cert pointing its CRL at localhost gets no verdict instead of a fetch.
	pki := newTestPKI(t, nil, []string{"http://127.0.0.1:1/crl"})
	r := &Result{Leaf: pki.leaf, Issuer: pki.ca}
	CheckRevocation(context.Background(), r)
	if r.RevocationStatus != "" {
		t.Errorf("loopback CRL URL: got %q, want no verdict", r.RevocationStatus)
	}
}
