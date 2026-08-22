package provx

import "testing"

func TestParseIssuer(t *testing.T) {
	good := []struct{ in, url, host string }{
		{"https://oidc.cloud.formae.ai", "https://oidc.cloud.formae.ai", "oidc.cloud.formae.ai"},
		{"https://e2e-b.s3.us-west-2.amazonaws.com", "https://e2e-b.s3.us-west-2.amazonaws.com", "e2e-b.s3.us-west-2.amazonaws.com"},
	}
	for _, c := range good {
		got, err := ParseIssuer(c.in)
		if err != nil || got.URL() != c.url || got.Host() != c.host {
			t.Fatalf("ParseIssuer(%q) = %v,%v / %v", c.in, got.URL(), got.Host(), err)
		}
	}
	bad := []string{
		"", "https://oidc.cloud.formae.ai/", "http://oidc.cloud.formae.ai",
		"https://user@host", "https://host/path", "https://host?q=1", "https://host#f",
		"https://host?", "https://host#", // empty query/fragment markers
		"https://host:443",     // port
		"https://",             // no host
		"oidc.cloud.formae.ai", // no scheme
	}
	for _, in := range bad {
		if _, err := ParseIssuer(in); err == nil {
			t.Fatalf("ParseIssuer(%q): want error", in)
		}
	}
}
