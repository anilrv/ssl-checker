package main

import (
	"context"
	"fmt"
	"time"

	"sslcheckerfunc/certprobe"
	"sslcheckerfunc/geoip"
	"sslcheckerfunc/ssrfguard"
	"sslcheckerfunc/whois"
)

func check(host string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("=== %s ===\n", host)
	ip, err := ssrfguard.ResolvePublicIP(ctx, host)
	if err != nil {
		fmt.Println("SSRF-GUARD ERROR:", err)
		return
	}
	res, err := certprobe.Probe(ctx, ip, host)
	if err != nil {
		fmt.Println("PROBE ERROR:", err)
		return
	}
	fmt.Printf("subject org=%q  issuer org=%q\n", res.SubjectOrg, res.IssuerOrg)
	fmt.Printf("chainLength=%d chainComplete=%v chainVerified=%v leafSelfSigned=%v\n",
		res.ChainLength, res.ChainComplete, res.ChainVerified, res.LeafSelfSigned)
	fmt.Printf("alpn=%q ocspStapled=%v sctCount=%d handshakeMs=%d server=%q poweredBy=%q\n",
		res.ALPNProtocol, res.OCSPStapled, res.SCTCount, res.HandshakeMs, res.ServerHeader, res.PoweredBy)

	if geo := geoip.Lookup(ctx, ip); geo != nil {
		fmt.Printf("geo: city=%q country=%q code=%q flag=%q flagData=%dB asn=%q asName=%q\n",
			geo.City, geo.Country, geo.CountryCode, geo.CountryFlag, len(geo.CountryFlagData), geo.ASN, geo.ASName)
	} else {
		fmt.Println("geo: unavailable")
	}

	if wh := whois.Lookup(ctx, host); wh != nil {
		fmt.Printf("whois: registrar=%q created=%v expires=%v providers=%v ownerOrg=%q\n",
			wh.RegistrarName, wh.Created, wh.Expires, wh.DetectedProviders, wh.OwnerOrg)
	} else {
		fmt.Println("whois: unavailable")
	}
}

func main() {
	check("make.powerapps.com")
	check("self-signed.badssl.com")
	check("untrusted-root.badssl.com")
	check("www.anilrv.in")
	check("www.google.com")
	check("news.google.com")
}
