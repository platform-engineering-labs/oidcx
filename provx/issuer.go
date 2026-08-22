package provx

import (
	"fmt"
	"net/url"
	"strings"
)

// Issuer is the outbound identity issuer in the two spellings AWS needs:
// the canonical https origin (the OIDC provider Url) and the scheme-less
// host used in the provider ARN and trust-policy condition keys. Fields
// are unexported so an Issuer only exists via ParseIssuer.
type Issuer struct {
	urlStr string
	host   string
}

func (i Issuer) URL() string  { return i.urlStr }
func (i Issuer) Host() string { return i.host }

// ParseIssuer accepts only a canonical https origin: no userinfo, port,
// path, query or fragment (not even empty markers), no trailing slash.
// What the caller pins is byte-for-byte what appears in the artifacts.
func ParseIssuer(raw string) (Issuer, error) {
	if raw == "" {
		return Issuer{}, fmt.Errorf("issuer is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Issuer{}, fmt.Errorf("issuer %q: %w", raw, err)
	}
	switch {
	case u.Scheme != "https",
		u.User != nil,
		u.Host == "",
		u.Port() != "",
		u.Path != "",
		u.RawQuery != "" || u.ForceQuery,
		u.Fragment != "" || strings.Contains(raw, "#"),
		strings.HasSuffix(raw, "/"):
		return Issuer{}, fmt.Errorf("issuer %q is not a canonical https origin", raw)
	}
	return Issuer{urlStr: "https://" + u.Host, host: u.Host}, nil
}
