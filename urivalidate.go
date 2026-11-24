package osin

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// defaultPorts holds the default port for the schemes that get their
// implicit port normalized away. Ports that were explicitly registered are
// still compared, only the default (implicit) port is treated as equivalent.
var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
}

// normalizeHost lowercases scheme and host and strips the implicit default
// port so that equivalent spellings (mixed case, an explicit default port)
// compare equal. The returned host keeps the original spelling for the value
// persisted on the redirect URL.
func normalizeHost(rawurl *url.URL) string {
	scheme := strings.ToLower(rawurl.Scheme)

	host := strings.ToLower(rawurl.Hostname())
	ipv6 := strings.HasPrefix(rawurl.Host, "[")
	port := rawurl.Port()
	if defaultPort, ok := defaultPorts[scheme]; ok && port == defaultPort {
		port = ""
	}

	if port == "" {
		if ipv6 {
			host = "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// error returned when validation don't match
type UriValidationError string

func (e UriValidationError) Error() string {
	return string(e)
}

func newUriValidationError(msg string, base string, redirect string) UriValidationError {
	return UriValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// ParseUrls parses URLs, resolving references to the base url
func ParseUrls(baseUrl, redirectUrl string) (retBaseUrl, retRedirectUrl *url.URL, err error) {
	var base, redirect *url.URL
	// parse base url
	if base, err = url.Parse(baseUrl); err != nil {
		return nil, nil, err
	}

	// parse redirect url
	if redirect, err = url.Parse(redirectUrl); err != nil {
		return nil, nil, err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, newUriValidationError("url must not include fragment.", baseUrl, redirectUrl)
	}

	// Scheme must match (case-insensitive, the scheme is case-insensitive)
	baseScheme := strings.ToLower(base.Scheme)
	redirectScheme := strings.ToLower(redirect.Scheme)
	if redirectScheme != baseScheme {
		return nil, nil, newUriValidationError("scheme mismatch", baseUrl, redirectUrl)
	}

	var (
		redirectMatch bool
		host          string
	)

	baseHost := normalizeHost(base)
	redirectHost := normalizeHost(redirect)

	// verify the hosts match
	if redirectHost == baseHost {
		redirectMatch = true
		host = baseHost
	} else if baseIP := net.ParseIP(base.Hostname()); baseIP != nil && baseIP.IsLoopback() && baseScheme == "http" {
		// if the registered redirect URI is lookback, then match the input redirect without the port.
		if redirectIP := net.ParseIP(redirect.Hostname()); redirectIP != nil && redirectIP.IsLoopback() {
			redirectMatch = true
			host = redirectHost
		}
	}

	// Hosts must match
	if !redirectMatch {
		return nil, nil, newUriValidationError("host mismatch", baseUrl, redirectUrl)
	}

	// resolve references to base url
	retBaseUrl = (&url.URL{Scheme: baseScheme, Host: host}).ResolveReference(&url.URL{Path: base.Path})
	retRedirectUrl = (&url.URL{Scheme: baseScheme, Host: host}).ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})
	return
}

// ValidateUriList validates that redirectUri is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func ValidateUriList(baseUriList string, redirectUri string, separator string) (realRedirectUri string, err error) {
	realRedirectUri, _, err = ValidateUriListWithBase(baseUriList, redirectUri, separator)
	return
}

// ValidateUriListWithBase behaves like ValidateUriList but also returns the
// registered base URI that matched. The matched base is the piece of
// information the token endpoint needs to know which of the client's
// configured redirect URIs was selected during authorization.
func ValidateUriListWithBase(baseUriList string, redirectUri string, separator string) (realRedirectUri string, matchedBaseUri string, err error) {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseUriList, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseUriList)
	}

	for _, sitem := range slist {
		sitem = strings.TrimSpace(sitem)
		realRedirectUri, err = ValidateUri(sitem, redirectUri)
		// validated, return no error
		if err == nil {
			return realRedirectUri, sitem, nil
		}

		// if there was an error that is not a validation error, return it
		if _, iok := err.(UriValidationError); !iok {
			return "", "", err
		}
	}

	return "", "", newUriValidationError("urls don't validate", baseUriList, redirectUri)
}

// ValidateUri validates that redirectUri is contained in baseUri
func ValidateUri(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	if baseUri == "" || redirectUri == "" {
		return "", errors.New("urls cannot be blank.")
	}

	base, redirect, err := ParseUrls(baseUri, redirectUri)
	if err != nil {
		return "", err
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return redirect.String(), nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return "", newUriValidationError("path prefix doesn't match", baseUri, redirectUri)
	}

	return redirect.String(), nil
}

// SameRedirectUri reports whether redirectUri is a valid redirect for the
// registered baseUri. It applies the exact same rules as ValidateUri and is
// the single predicate shared by the authorization and token endpoints, so
// the two phases can never disagree about whether two callbacks are the same.
func SameRedirectUri(baseUri string, redirectUri string) bool {
	_, err := ValidateUri(baseUri, redirectUri)
	return err == nil
}

// FirstUri returns the first uri from a URI list
func FirstUri(baseUriList string, separator string) string {
	if separator != "" {
		slist := strings.Split(baseUriList, separator)
		if len(slist) > 0 {
			return slist[0]
		}
	} else {
		return baseUriList
	}

	return ""
}
