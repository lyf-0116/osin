package osin

import (
	"fmt"
	"testing"
)

func TestURIValidate(t *testing.T) {
	valid := []struct {
		name              string
		clientRedirectURI string
		inputRedirectURI  string
		normalized        string
	}{
		{
			"Exact match",
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
		},
		{
			"Only domain, exact match",
			"http://google.com",
			"http://google.com",
			"http://google.com",
		},
		{
			"Only domain, with subpath",
			"http://google.com",
			"http://google.com/redirect",
			"http://google.com/redirect",
		},
		{
			"Trailing slash",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			"Exact match with trailing slash",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			"Subpath",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			"Subpath with trailing slash",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			"Subpath with things that are close to path traversals, but aren't",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/.../..implementation../...",
			"http://www.google.com/myapp/.../..implementation../...",
		},
		{
			"If the allowed basepath contains path traversals, allow them?",
			"http://www.google.com/traversal/../allowed",
			"http://www.google.com/traversal/../allowed/with/subpath",
			"http://www.google.com/allowed/with/subpath",
		},
		{
			"Backslashes",
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure/redirect/\\../\\../\\../evil",
			"https://mysafewebsite.com/secure/redirect/%5C../%5C../%5C../evil",
		},
		{
			"Query string must be kept",
			"http://www.google.com/myapp/redir",
			"http://www.google.com/myapp/redir?a=1&b=2",
			"http://www.google.com/myapp/redir?a=1&b=2",
		},
		{
			"IPv4 loopback address",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:8081/callback",
			"http://127.0.0.1:8081/callback",
		},
		{
			"Uncommon IPv4 loopback address",
			"http://127.0.0.1/callback",
			"http://127.0.0.8:8081/callback",
			"http://127.0.0.8:8081/callback",
		},
		{
			"IPv6 loopback address",
			"http://127.0.0.1/callback",
			"http://[::1]:8081/callback",
			"http://[::1]:8081/callback",
		},
		{
			"No port in IPv4 loopback address",
			"http://127.0.0.1/callback",
			"http://127.0.0.1/callback",
			"http://127.0.0.1/callback",
		},
		{
			"No port in IPv6 loopback address",
			"http://127.0.0.1/callback",
			"http://[0:0:0:0:0:0:0:1]/callback",
			"http://[0:0:0:0:0:0:0:1]/callback",
		},
		{
			"Uppercase host",
			"http://example.com/callback",
			"http://EXAMPLE.COM/callback",
			"http://example.com/callback",
		},
		{
			"Uppercase scheme",
			"http://example.com/callback",
			"HTTP://example.com/callback",
			"http://example.com/callback",
		},
		{
			"Explicit default http port",
			"http://example.com/callback",
			"http://example.com:80/callback",
			"http://example.com/callback",
		},
		{
			"Explicit default https port",
			"https://example.com/callback",
			"https://example.com:443/callback",
			"https://example.com/callback",
		},
		{
			"Default port on the registered uri",
			"https://example.com:443/callback",
			"https://example.com/callback",
			"https://example.com/callback",
		},
		{
			"Normalized loopback keeps the requested path spelling",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:8081/callback/",
			"http://127.0.0.1:8081/callback/",
		},
	}
	for _, v := range valid {
		t.Run(fmt.Sprintf("valid/%s", v.name), func(t *testing.T) {
			if realRedirectUri, err := ValidateUri(v.clientRedirectURI, v.inputRedirectURI); err != nil {
				t.Errorf("Expected ValidateUri(%s, %s) to succeed, got %v", v.clientRedirectURI, v.inputRedirectURI, err)
			} else if realRedirectUri != v.normalized {
				t.Errorf("Expected ValidateUri(%s, %s) to return uri %s, got %s", v.clientRedirectURI, v.inputRedirectURI, v.normalized, realRedirectUri)
			}
		})
	}

	invalid := []struct {
		name              string
		clientRedirectURI string
		inputRedirectURI  string
	}{
		{
			"Doesn't satisfy base path",
			"http://localhost:14000/appauth",
			"http://localhost:14000/app",
		},
		{
			"Doesn't satisfy base path",
			"http://localhost:14000/app/",
			"http://localhost:14000/app",
		},
		{
			"Not a subpath of base path",
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauthmodifiedpath",
		},
		{
			"Host mismatch",
			"http://www.google.com/myapp",
			"http://www2.google.com/myapp",
		},
		{
			"Scheme mismatch",
			"http://www.google.com/myapp",
			"https://www.google.com/myapp",
		},
		{
			"Path traversal",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/..",
		},
		{
			"Embedded path traversal",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/../test",
		},
		{
			"Not a subpath",
			"http://www.google.com/myapp",
			"http://www.google.com/myapp../test",
		},
		{
			"Backslashes",
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure%2fredirect/../evil",
		},
		{
			"Mismatching ports",
			"https://example.com:8081/redirect",
			"https://example.com:8080/redirect",
		},
		{
			"Non loopback address",
			"http://127.0.0.1/callback",
			"http://localhost:8080/callback",
		},
		{
			"Invalid input redirect URI",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:abc/callback",
		},
		{
			"Non http scheme in redirect URI",
			"custom://127.0.0.1/callback",
			"custom://127.0.0.1:8080/callback",
		},
		{
			"Redirect URI is loopback, input is a domain name with port",
			"http://127.0.0.1/callback",
			"http://example.com:8081/callback",
		},
		{
			"Redirect URI is loopback, input is a domain name without port",
			"http://127.0.0.1/callback",
			"http://example.com/callback",
		},
		{
			"Non-default ports still mismatch",
			"http://example.com:8080/callback",
			"http://example.com:9090/callback",
		},
		{
			"Default port does not make an explicit non-default port equivalent",
			"http://example.com:8080/callback",
			"http://example.com:80/callback",
		},
	}
	for _, v := range invalid {
		t.Run(fmt.Sprintf("invalid/%s", v.name), func(t *testing.T) {
			if _, err := ValidateUri(v.clientRedirectURI, v.inputRedirectURI); err == nil {
				t.Errorf("Expected ValidateUri(%s, %s) to fail", v.clientRedirectURI, v.inputRedirectURI)
			}
		})
	}
}

func TestURIListValidate(t *testing.T) {
	// V1
	if _, err := ValidateUriList("http://localhost:14000/appauth", "http://localhost:14000/appauth", ""); err != nil {
		t.Errorf("V1: %s", err)
	}

	// V2
	if _, err := ValidateUriList("http://localhost:14000/appauth", "http://localhost:14000/app", ""); err == nil {
		t.Error("V2 should have failed")
	}

	// V3
	if _, err := ValidateUriList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/appauth", ";"); err != nil {
		t.Errorf("V3: %s", err)
	}

	// V4
	if _, err := ValidateUriList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/app", ";"); err == nil {
		t.Error("V4 should have failed")
	}
}

func TestValidateUriListWithBaseReturnsMatchedBase(t *testing.T) {
	list := "https://a.example.com/cb;https://b.example.com/cb"

	real, base, err := ValidateUriListWithBase(list, "https://b.example.com/cb", ";")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != "https://b.example.com/cb" {
		t.Fatalf("expected matched base to be the second entry, got %q", base)
	}
	if real != "https://b.example.com/cb" {
		t.Fatalf("unexpected normalized redirect uri: %q", real)
	}

	// spacing around the separator must not change which base is selected
	real, base, err = ValidateUriListWithBase(
		"https://a.example.com/cb ; https://b.example.com/cb",
		"https://B.example.com/cb", ";")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != "https://b.example.com/cb" {
		t.Fatalf("expected trimmed matched base, got %q", base)
	}
	if real != "https://b.example.com/cb" {
		t.Fatalf("expected normalized host, got %q", real)
	}

	if _, _, err := ValidateUriListWithBase(list, "https://c.example.com/cb", ";"); err == nil {
		t.Fatal("expected an error for a redirect that matches no base")
	}
}

func TestSameRedirectUri(t *testing.T) {
	equivalent := [][2]string{
		{"http://example.com/cb", "http://EXAMPLE.COM/cb"},
		{"https://example.com/cb", "https://example.com:443/cb"},
		{"http://www.google.com/myapp", "http://www.google.com/myapp/"},
		{"http://127.0.0.1/callback", "http://127.0.0.1:8081/callback"},
	}
	for _, pair := range equivalent {
		if !SameRedirectUri(pair[0], pair[1]) {
			t.Errorf("expected SameRedirectUri(%q, %q) to be true", pair[0], pair[1])
		}
	}

	different := [][2]string{
		{"http://example.com/cb", "https://example.com/cb"},
		{"http://example.com/cb", "http://other.com/cb"},
		{"http://example.com:8080/cb", "http://example.com:9090/cb"},
	}
	for _, pair := range different {
		if SameRedirectUri(pair[0], pair[1]) {
			t.Errorf("expected SameRedirectUri(%q, %q) to be false", pair[0], pair[1])
		}
	}
}
