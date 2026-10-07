package validator

import (
	"crypto/x509"
	"net"
	"strings"
)

// constraintsSet is the cumulative, effective name-constraint set while
// walking a path from the root downwards.
//
// Semantics follow RFC 5280 4.2.1.10:
//   - permitted subtrees are intersected level by level. A name must match at
//     least one subtree asserted by EVERY CA level that defined a permitted
//     subtree, so a looser lower CA can never widen an upper CA's space and
//     conflicting permitted subtrees fail closed;
//   - excluded subtrees are a cumulative union: a name excluded by ANY level
//     is forbidden.
type constraintsSet struct {
	permittedDNS   [][]string
	permittedIPs   [][]*net.IPNet
	permittedMails [][]string

	excludedDNS   []string
	excludedIPs   []*net.IPNet
	excludedMails []string
}

// merge folds the constraints declared in one CA certificate into the
// effective set. merge must be applied root-first.
func (cs *constraintsSet) merge(c *x509.Certificate) error {
	if len(c.PermittedDNSDomains) > 0 {
		cs.permittedDNS = append(cs.permittedDNS, lowerAll(c.PermittedDNSDomains))
	}
	cs.excludedDNS = append(cs.excludedDNS, lowerAll(c.ExcludedDNSDomains)...)
	if len(c.PermittedIPRanges) > 0 {
		cs.permittedIPs = append(cs.permittedIPs, append([]*net.IPNet(nil), c.PermittedIPRanges...))
	}
	cs.excludedIPs = append(cs.excludedIPs, c.ExcludedIPRanges...)
	if len(c.PermittedEmailAddresses) > 0 {
		cs.permittedMails = append(cs.permittedMails, lowerAll(c.PermittedEmailAddresses))
	}
	cs.excludedMails = append(cs.excludedMails, lowerAll(c.ExcludedEmailAddresses)...)
	return nil
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}

// checkCertificate applies the effective constraints to all SAN identifiers
// present in cert. A certificate that does not carry a given name type is not
// constrained in that type (RFC 5280 4.2.1.10); every identifier present must
// satisfy all levels.
func (cs *constraintsSet) checkCertificate(cert *x509.Certificate, idx int) error {
	for _, name := range cert.DNSNames {
		if err := cs.checkDNS(strings.ToLower(name)); err != nil {
			return certErr(CodeNameConstraints, idx, cert, "DNS name %q: %v", name, err)
		}
	}
	for _, ip := range cert.IPAddresses {
		if err := cs.checkIP(ip); err != nil {
			return certErr(CodeNameConstraints, idx, cert, "IP %s: %v", ip.String(), err)
		}
	}
	for _, mail := range cert.EmailAddresses {
		if err := cs.checkMail(strings.ToLower(mail)); err != nil {
			return certErr(CodeNameConstraints, idx, cert, "email %q: %v", mail, err)
		}
	}
	return nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

var errConstraint = constErr("violates effective name constraints")

func (cs *constraintsSet) checkDNS(name string) error {
	for _, d := range cs.excludedDNS {
		if dnsMatch(name, d) {
			return errConstraint
		}
	}
	for _, level := range cs.permittedDNS {
		matched := false
		for _, d := range level {
			if dnsMatch(name, d) {
				matched = true
				break
			}
		}
		if !matched {
			return errConstraint
		}
	}
	return nil
}

func (cs *constraintsSet) checkIP(ip net.IP) error {
	for _, n := range cs.excludedIPs {
		if n.Contains(ip) {
			return errConstraint
		}
	}
	for _, level := range cs.permittedIPs {
		matched := false
		for _, n := range level {
			if n.Contains(ip) {
				matched = true
				break
			}
		}
		if !matched {
			return errConstraint
		}
	}
	return nil
}

func (cs *constraintsSet) checkMail(address string) error {
	for _, d := range cs.excludedMails {
		if mailMatch(address, d) {
			return errConstraint
		}
	}
	for _, level := range cs.permittedMails {
		matched := false
		for _, d := range level {
			if mailMatch(address, d) {
				matched = true
				break
			}
		}
		if !matched {
			return errConstraint
		}
	}
	return nil
}

// dnsMatch implements RFC 5280 DNS constraint matching: a leading-dot
// constraint (".example.com") matches the domain and sub-domains; a bare
// constraint matches the name itself and sub-domains too (we accept both
// encodings, which is common in locally generated test data).
func dnsMatch(name, constraint string) bool {
	constraint = strings.TrimPrefix(strings.TrimSuffix(constraint, "."), ".")
	name = strings.TrimSuffix(name, ".")
	if name == constraint {
		return true
	}
	return strings.HasSuffix(name, "."+constraint)
}

// mailMatch implements rfc822Name constraint matching: exact mailbox, or a
// domain-part match when the constraint carries no local part.
func mailMatch(address, constraint string) bool {
	constraint = strings.TrimPrefix(constraint, ".")
	if strings.Contains(constraint, "@") {
		return address == constraint
	}
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return false
	}
	return dnsMatch(address[at+1:], constraint)
}
