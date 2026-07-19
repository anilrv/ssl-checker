// Package certprobe performs a real TLS handshake (using Go's stdlib crypto/tls, not a
// hand-rolled parser) against a vetted IP address, with certificate verification
// disabled — we WANT to inspect invalid/self-signed/expired certificates, not reject
// the connection because of them.
package certprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

type Result struct {
	SubjectOrg  string
	SubjectCN   string
	IssuerOrg   string
	IssuerCN    string
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	Protocol    string
	CipherSuite string

	// ChainLength is how many certificates the server presented (leaf + intermediates).
	ChainLength int
	// ChainComplete: did the server send a structurally complete path (i.e. does the
	// topmost presented certificate terminate in a self-signed root)? False means the
	// server is missing an intermediate — a server misconfiguration, independent of
	// whether that root would even be trusted.
	ChainComplete bool
	// ChainVerified: does the path actually verify against the system trust store?
	// Go's x509.Verify does NOT fetch missing intermediates via AIA the way browsers
	// do, so this can (correctly) be false for a site that "works" in a browser that
	// cached the missing intermediate.
	ChainVerified    bool
	ChainVerifyError string // empty if verified

	// LeafSelfSigned is a cryptographic check (the leaf's signature verifies against
	// its own public key) — NOT a string comparison of issuer/subject Organization,
	// which false-positives whenever a CA and the leaf happen to share an org name
	// (e.g. a company running its own subordinate CA for its own domains).
	LeafSelfSigned bool

	// Leaf key/signature details for the weak-crypto rules (and display). The weakness
	// CLASSIFICATION lives here because it's x509 knowledge; the POLICY of turning it
	// into an issue lives in the caller, matching the LeafSelfSigned pattern above.
	SignatureAlgorithm string // e.g. "SHA256-RSA" (x509.SignatureAlgorithm.String())
	WeakSignature      bool   // leaf signed with an MD2/MD5/SHA-1-based algorithm
	KeyType            string // "RSA", "ECDSA", "Ed25519"; "" if unrecognized
	KeyBits            int    // RSA modulus bits / ECDSA curve bits / 256 for Ed25519; 0 if unknown

	// Raw material for CheckRevocation (revocation.go): the leaf, the presented
	// intermediate that actually signed it (nil when the server sent none — no
	// revocation evidence can be validated without it), and the OCSP response stapled
	// during the handshake, kept verbatim so it can be parsed without a re-handshake.
	Leaf          *x509.Certificate
	Issuer        *x509.Certificate
	RawOCSPStaple []byte

	// Filled by CheckRevocation, not Probe: "good" | "revoked" | "unknown", empty when
	// the check couldn't run or nothing definitive came back.
	RevocationStatus string
	RevocationSource string // "stapled-ocsp" | "ocsp" | "crl"

	// The fields below come free from the same handshake (ALPN/OCSP/SCT), or from a
	// single lightweight HTTP request reusing the already-open TLS connection (Server/
	// PoweredBy) — never a second connection. All best-effort: a failure just leaves
	// the corresponding field at its zero value rather than failing the whole probe.
	ALPNProtocol string // e.g. "h2" or "http/1.1"; empty if not negotiated
	OCSPStapled  bool
	SCTCount     int
	HandshakeMs  int64

	ServerHeader string
	PoweredBy    string
}

func protocolName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func firstOrEmpty(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// weakSignatureAlgorithm reports whether alg is based on a broken hash (MD2/MD5/SHA-1).
// Public CAs stopped issuing these years ago, so in practice this fires on self-signed
// and private-CA certificates — which is exactly where a checker still adds value.
func weakSignatureAlgorithm(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// publicKeyInfo classifies a leaf public key for the weak-key rule. Unrecognized key
// types (including long-dead DSA) come back as ("", 0) and are simply not judged.
func publicKeyInfo(pub any) (keyType string, bits int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}

// leafIssuer picks the presented certificate that actually signed the leaf — a
// cryptographic check, not a subject/issuer name comparison, for the same reason as
// isSelfSigned below. Returns nil when the server presented no usable issuer.
func leafIssuer(certs []*x509.Certificate) *x509.Certificate {
	leaf := certs[0]
	for _, c := range certs[1:] {
		if leaf.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

// isSelfSigned checks pure cryptographic self-signature (does this cert's own public
// key verify its own signature), NOT cert.CheckSignatureFrom(cert) — that method also
// enforces CA/KeyUsage constraints, which real-world self-signed test/leaf certs often
// lack (they were never meant to be a signing CA), causing false negatives.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// verifyChain reports chain completeness (structural) and trust (verified against the
// system root store) as two separate signals — see the Result field docs above.
func verifyChain(certs []*x509.Certificate) (complete bool, verified bool, verifyErr string) {
	if len(certs) == 0 {
		return false, false, "no certificate presented"
	}
	leaf := certs[0]
	top := certs[len(certs)-1]
	complete = isSelfSigned(top)

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		// DNSName intentionally omitted: hostname/SAN matching is done separately
		// with our own wildcard logic, so it isn't conflated with trust-path errors.
	})
	if err == nil {
		return complete, true, ""
	}

	if invalid, ok := err.(x509.CertificateInvalidError); ok && invalid.Reason == x509.Expired {
		// Already covered by our own expired/not-yet-valid checks — don't double-report
		// the same root cause as a separate "untrusted" issue.
		return complete, true, ""
	}
	return complete, false, err.Error()
}

// Probe connects to ip:443, presents SNI=hostname, and returns the leaf certificate's
// details plus the actually-negotiated protocol/cipher (real handshake, full version
// range offered — this reports what a normal browser would actually negotiate).
func Probe(ctx context.Context, ip net.IP, hostname string) (*Result, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	addr := net.JoinHostPort(ip.String(), "443")

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp connect failed: %w", err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(8 * time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // deliberate: we want to see invalid certs, not reject the connection
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"}, // enables ALPN negotiation, otherwise never offered
	})
	defer tlsConn.Close()

	handshakeStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	handshakeMs := time.Since(handshakeStart).Milliseconds()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server presented no certificate")
	}
	leaf := state.PeerCertificates[0]

	complete, verified, verifyErr := verifyChain(state.PeerCertificates)
	keyType, keyBits := publicKeyInfo(leaf.PublicKey)

	result := &Result{
		SubjectOrg:  firstOrEmpty(leaf.Subject.Organization),
		SubjectCN:   leaf.Subject.CommonName,
		IssuerOrg:   firstOrEmpty(leaf.Issuer.Organization),
		IssuerCN:    leaf.Issuer.CommonName,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		DNSNames:    leaf.DNSNames,
		Protocol:    protocolName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),

		ChainLength:      len(state.PeerCertificates),
		ChainComplete:    complete,
		ChainVerified:    verified,
		ChainVerifyError: verifyErr,

		LeafSelfSigned: isSelfSigned(leaf),

		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		WeakSignature:      weakSignatureAlgorithm(leaf.SignatureAlgorithm),
		KeyType:            keyType,
		KeyBits:            keyBits,

		Leaf:          leaf,
		Issuer:        leafIssuer(state.PeerCertificates),
		RawOCSPStaple: state.OCSPResponse,

		ALPNProtocol: state.NegotiatedProtocol,
		OCSPStapled:  len(state.OCSPResponse) > 0,
		SCTCount:     len(state.SignedCertificateTimestamps),
		HandshakeMs:  handshakeMs,
	}

	// Best-effort only: reuses this same already-open connection (no second handshake).
	// Any failure here just leaves ServerHeader/PoweredBy empty — the probe already
	// succeeded once the certificate was read above, and must not fail because of this.
	result.ServerHeader, result.PoweredBy = fetchServerHeaders(rawConn, tlsConn, hostname)

	return result, nil
}

// fetchServerHeaders sends a minimal HEAD request over the already-established tlsConn
// and reads back just the response headers we care about. Deliberately does not reuse
// ctx's deadline (which may already be nearly exhausted by the handshake above) — a
// short, fixed budget of its own so this optional step can't meaningfully delay the
// overall probe even in the worst case.
func fetchServerHeaders(rawConn net.Conn, tlsConn *tls.Conn, hostname string) (server, poweredBy string) {
	if err := rawConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", ""
	}

	// A connection that negotiated ALPN "h2" only understands the HTTP/2 wire format from
	// this point on — writing a raw HTTP/1.1 request line over it doesn't get rejected
	// gracefully, it just never produces a parseable response, so this HAS to branch here
	// rather than always speaking HTTP/1.1.
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return fetchServerHeadersH2(tlsConn, hostname)
	}

	req, err := http.NewRequest(http.MethodHead, "https://"+hostname+"/", nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Connection", "close")
	req.Host = hostname

	if err := req.Write(tlsConn); err != nil {
		return "", ""
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	return resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")
}

// fetchServerHeadersH2 sends the same best-effort HEAD request as fetchServerHeaders, but
// over the HTTP/2 framing required once ALPN has negotiated "h2" on this connection.
func fetchServerHeadersH2(tlsConn *tls.Conn, hostname string) (server, poweredBy string) {
	req, err := http.NewRequest(http.MethodHead, "https://"+hostname+"/", nil)
	if err != nil {
		return "", ""
	}
	req.Host = hostname

	cc, err := (&http2.Transport{}).NewClientConn(tlsConn)
	if err != nil {
		return "", ""
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	return resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")
}

// SupportsLegacyProtocol reports whether the server still completes a handshake when
// the client offers ONLY the given legacy version (e.g. tls.VersionTLS10) — i.e.
// whether that weak protocol is still enabled server-side.
func SupportsLegacyProtocol(ctx context.Context, ip net.IP, hostname string, version uint16) bool {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	addr := net.JoinHostPort(ip.String(), "443")

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(6 * time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	defer tlsConn.Close()

	return tlsConn.HandshakeContext(ctx) == nil
}
