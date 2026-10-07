package validator

import (
	"crypto/x509"
	"net"
	"net/mail"
	"strings"
)

// MatchHostname checks DNS names and IP addresses exactly like the standard
// library (RFC 6125 wildcard rules, IP literal comparison). Only SAN
// identifiers are honored per RFC 6125 / CA/B baseline requirements; a Common
// Name can never extend or override SANs, so CN aliases cannot bypass checks.
func MatchHostname(cert *x509.Certificate, host string) error {
	return cert.VerifyHostname(host)
}

// MatchEmail checks a target mailbox against rfc822Name SAN entries. Entries
// may be exact addresses or a leading-dot domain (".example.com") / bare
// domain ("example.com") matching any mailbox at that domain or a subdomain.
func MatchEmail(cert *x509.Certificate, address string) error {
	addr, err := mail.ParseAddress(address)
	if err == nil {
		address = addr.Address
	}
	address = strings.ToLower(strings.TrimSpace(address))
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return certErr(CodeHostnameMismatch, 0, cert, "malformed email address %q", address)
	}
	local, domain := address[:at], address[at+1:]
	if local == "" || domain == "" {
		return certErr(CodeHostnameMismatch, 0, cert, "malformed email address %q", address)
	}
	for _, san := range cert.EmailAddresses {
		san = strings.ToLower(strings.TrimSpace(san))
		if san == address {
			return nil
		}
		if strings.HasPrefix(san, ".") && dnsInDomain(domain, san[1:]) {
			return nil
		}
		if !strings.Contains(san, "@") && dnsInDomain(domain, san) {
			return nil
		}
	}
	return certErr(CodeHostnameMismatch, 0, cert, "no SAN email matches %q", address)
}

// MatchIP checks an IP literal against iPAddress SAN entries.
func MatchIP(cert *x509.Certificate, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return certErr(CodeHostnameMismatch, 0, cert, "invalid IP literal %q", ip)
	}
	for _, candidate := range cert.IPAddresses {
		if candidate.Equal(parsed) {
			return nil
		}
	}
	return certErr(CodeHostnameMismatch, 0, cert, "no SAN IP matches %s", ip)
}

// dnsInDomain reports whether host is equal to domain or a sub-domain of it.
// Labels are compared case-insensitively; IDN/ASCII forms must already match.
func dnsInDomain(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}
