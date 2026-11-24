package osin

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAccessAuthorizationCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

// TestAuthorizationCodeRedirectUriConsistency covers the case where the
// authorization and token endpoints previously applied different redirect
// semantics: authorization accepted a normalized match while the token
// endpoint demanded a raw string equality, producing a spurious
// "Redirect uri is different" error. It also verifies that with several
// registered callbacks the entry selected during authorization is carried
// with the authorization code and re-used during token exchange.
func TestAuthorizationCodeRedirectUriConsistency(t *testing.T) {
	testcases := map[string]struct {
		registeredUris string
		authorizeUri   string
		tokenUri       string
		expectMatched  string
		expectError    bool
	}{
		"uppercase host accepted at both phases": {
			registeredUris: "http://example.com/callback",
			authorizeUri:   "http://EXAMPLE.COM/callback",
			tokenUri:       "http://example.com/callback",
			expectMatched:  "http://example.com/callback",
		},
		"implicit default port accepted at both phases": {
			registeredUris: "https://example.com/callback",
			authorizeUri:   "https://example.com/callback",
			tokenUri:       "https://example.com:443/callback",
			expectMatched:  "https://example.com/callback",
		},
		"trailing slash accepted at both phases": {
			registeredUris: "http://example.com/callback",
			authorizeUri:   "http://example.com/callback/",
			tokenUri:       "http://example.com/callback",
			expectMatched:  "http://example.com/callback",
		},
		"second registered callback is selected and re-used": {
			registeredUris: "http://a.example.com/callback;http://b.example.com/callback",
			authorizeUri:   "http://b.example.com/callback",
			tokenUri:       "http://B.example.com/callback",
			expectMatched:  "http://b.example.com/callback",
		},
		"callback registered on a different entry is rejected": {
			registeredUris: "http://a.example.com/callback;http://b.example.com/callback",
			authorizeUri:   "http://a.example.com/callback",
			tokenUri:       "http://b.example.com/callback",
			expectMatched:  "http://a.example.com/callback",
			expectError:    true,
		},
		"unregistered host is rejected at token exchange": {
			registeredUris: "http://example.com/callback",
			authorizeUri:   "http://example.com/callback",
			tokenUri:       "http://evil.example.com/callback",
			expectMatched:  "http://example.com/callback",
			expectError:    true,
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			storage := NewTestingStorage()
			client := &DefaultClient{
				Id:          "multi",
				Secret:      "secret",
				RedirectUri: test.registeredUris,
			}
			if err := storage.SetClient(client.Id, client); err != nil {
				t.Fatal(err)
			}

			sconfig := NewServerConfig()
			sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
			sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
			sconfig.RedirectUriSeparator = ";"
			server := NewServer(sconfig, storage)
			server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
			server.AccessTokenGen = &TestingAccessTokenGen{}

			// authorization phase
			authResp := server.NewResponse()
			authReq, err := http.NewRequest("GET", "http://localhost/authorize", nil)
			if err != nil {
				t.Fatal(err)
			}
			authReq.Form = url.Values{
				"response_type": {string(CODE)},
				"client_id":     {client.Id},
				"state":         {"state"},
				"redirect_uri":  {test.authorizeUri},
			}
			ar := server.HandleAuthorizeRequest(authResp, authReq)
			if ar == nil {
				t.Fatalf("authorization request rejected: %v", authResp.InternalError)
			}
			ar.Authorized = true
			server.FinishAuthorizeRequest(authResp, authReq, ar)
			if authResp.IsError {
				t.Fatalf("authorization failed: %v", authResp.InternalError)
			}

			code, ok := authResp.Output["code"].(string)
			if !ok || code == "" {
				t.Fatalf("missing authorization code: %#v", authResp.Output)
			}

			stored, err := storage.LoadAuthorize(code)
			if err != nil {
				t.Fatalf("loading authorization data: %v", err)
			}
			if stored.RedirectBaseUri != test.expectMatched {
				t.Fatalf("expected stored base %q, got %q", test.expectMatched, stored.RedirectBaseUri)
			}

			// token exchange phase
			tokenResp := server.NewResponse()
			tokenReq, err := http.NewRequest("POST", "http://localhost/token", nil)
			if err != nil {
				t.Fatal(err)
			}
			tokenReq.SetBasicAuth(client.Id, client.Secret)
			tokenReq.Form = url.Values{
				"grant_type":   {string(AUTHORIZATION_CODE)},
				"code":         {code},
				"redirect_uri": {test.tokenUri},
			}
			tokenReq.PostForm = url.Values{}

			if accessReq := server.HandleAccessRequest(tokenResp, tokenReq); accessReq != nil {
				accessReq.Authorized = true
				server.FinishAccessRequest(tokenResp, tokenReq, accessReq)
			}

			if test.expectError {
				if !tokenResp.IsError || tokenResp.ErrorId != E_INVALID_REQUEST {
					t.Fatalf("expected invalid_request error, got %#v", tokenResp)
				}
				return
			}
			if tokenResp.IsError {
				t.Fatalf("token exchange failed: %v", tokenResp.InternalError)
			}
			if tokenResp.Type != DATA {
				t.Fatalf("expected token data response, got %v", tokenResp.Type)
			}
		})
	}
}

func TestAccessRefreshToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}
	//fmt.Printf("%+v", resp)

	if _, err := server.Storage.LoadRefresh("r9999"); err == nil {
		t.Fatalf("token was not deleted")
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessRefreshTokenSaveToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	server.Config.RetainTokenAfterRefresh = true
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}
	//fmt.Printf("%+v", resp)

	if _, err := server.Storage.LoadRefresh("r9999"); err != nil {
		t.Fatalf("token incorrectly deleted: %s", err.Error())
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessPassword(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "testing")
	req.Form.Set("password", "testing")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = ar.Username == "testing" && ar.Password == "testing"
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessClientCredentials(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d, dok := resp.Output["refresh_token"]; dok {
		t.Fatalf("Refresh token should not be generated: %s", d)
	}
}

func TestExtraScopes(t *testing.T) {
	if extraScopes("", "") == true {
		t.Fatalf("extraScopes returned true with empty scopes")
	}

	if extraScopes("a", "") == true {
		t.Fatalf("extraScopes returned true with less scopes")
	}

	if extraScopes("a b", "b a") == true {
		t.Fatalf("extraScopes returned true with matching scopes")
	}

	if extraScopes("a b", "b a c") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

	if extraScopes("", "a") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

}

// clientWithoutMatcher just implements the base Client interface
type clientWithoutMatcher struct {
	Id          string
	Secret      string
	RedirectUri string
}

func (c *clientWithoutMatcher) GetId() string            { return c.Id }
func (c *clientWithoutMatcher) GetSecret() string        { return c.Secret }
func (c *clientWithoutMatcher) GetRedirectUri() string   { return c.RedirectUri }
func (c *clientWithoutMatcher) GetUserData() interface{} { return nil }

func TestGetClientWithoutMatcher(t *testing.T) {
	myclient := &clientWithoutMatcher{
		Id:          "myclient",
		Secret:      "myclientsecret",
		RedirectUri: "http://www.example.com",
	}
	storage := &TestingStorage{clients: map[string]Client{myclient.Id: myclient}}
	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	// Ensure bad secret fails
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "invalidsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}

		if !w.IsError {
			t.Error("No error in response")
		}

		if w.ErrorId != E_UNAUTHORIZED_CLIENT {
			t.Errorf("Expected error %v, got %v", E_UNAUTHORIZED_CLIENT, w.ErrorId)
		}
	}

	// Ensure nonexistent client fails
	{
		auth := &BasicAuth{
			Username: "nonexistent",
			Password: "nonexistent",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}

		if !w.IsError {
			t.Error("No error in response")
		}

		if w.ErrorId != E_UNAUTHORIZED_CLIENT {
			t.Errorf("Expected error %v, got %v", E_UNAUTHORIZED_CLIENT, w.ErrorId)
		}
	}

	// Ensure good secret works
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "myclientsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != myclient {
			t.Errorf("Expected client, got nil with response: %v", w)
		}
	}
}

// clientWithMatcher implements the base Client interface and the ClientSecretMatcher interface
type clientWithMatcher struct {
	Id          string
	Secret      string
	RedirectUri string
}

func (c *clientWithMatcher) GetId() string            { return c.Id }
func (c *clientWithMatcher) GetSecret() string        { panic("called GetSecret"); return "" }
func (c *clientWithMatcher) GetRedirectUri() string   { return c.RedirectUri }
func (c *clientWithMatcher) GetUserData() interface{} { return nil }
func (c *clientWithMatcher) ClientSecretMatches(secret string) bool {
	return secret == c.Secret
}

func TestGetClientSecretMatcher(t *testing.T) {
	myclient := &clientWithMatcher{
		Id:          "myclient",
		Secret:      "myclientsecret",
		RedirectUri: "http://www.example.com",
	}
	storage := &TestingStorage{clients: map[string]Client{myclient.Id: myclient}}
	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	// Ensure bad secret fails, but does not panic (doesn't call GetSecret)
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "invalidsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}
	}

	// Ensure good secret works, but does not panic (doesn't call GetSecret)
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "myclientsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != myclient {
			t.Errorf("Expected client, got nil with response: %v", w)
		}
	}
}

func TestAccessAuthorizationCodePKCE(t *testing.T) {
	testcases := map[string]struct {
		Challenge       string
		ChallengeMethod string
		Verifier        string
		ExpectedError   string
	}{
		"good, plain": {
			Challenge: "12345678901234567890123456789012345678901234567890",
			Verifier:  "12345678901234567890123456789012345678901234567890",
		},
		"bad, plain": {
			Challenge:     "12345678901234567890123456789012345678901234567890",
			Verifier:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError: "invalid_grant",
		},
		"good, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"bad, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   "invalid_grant",
		},
		"missing from storage": {
			Challenge:       "",
			ChallengeMethod: "",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		sconfig := NewServerConfig()
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		server.Storage.SaveAuthorize(&AuthorizeData{
			Client:              testStorage.clients["public-client"],
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectUri:         "http://localhost:14000/appauth",
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: test.ChallengeMethod,
		})
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth("public-client", "")

		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		req.Form.Set("code_verifier", test.Verifier)
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			if test.ExpectedError == "" || test.ExpectedError != resp.ErrorId {
				t.Errorf("%s: unexpected error: %v, %v", k, resp.ErrorId, resp.StatusText)
				continue
			}
		}
		if test.ExpectedError == "" {
			if resp.Type != DATA {
				t.Fatalf("%s: Response should be data", k)
			}
			if d := resp.Output["access_token"]; d != "1" {
				t.Fatalf("%s: Unexpected access token: %s", k, d)
			}
			if d := resp.Output["refresh_token"]; d != "r1" {
				t.Fatalf("%s: Unexpected refresh token: %s", k, d)
			}
		}
	}
}
