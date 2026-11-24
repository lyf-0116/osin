package osin

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
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

func newAuthorizationCodeRequest(code string) *http.Request {
	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", code)
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)
	return req
}

func TestAccessAuthorizationCodeReplayRejected(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// first exchange succeeds and consumes the code
	first := server.NewResponse()
	if ar := server.HandleAccessRequest(first, newAuthorizationCodeRequest("9999")); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(first, newAuthorizationCodeRequest("9999"), ar)
	}
	if first.IsError {
		t.Fatalf("First exchange should succeed: %v", first.InternalError)
	}

	// the code must be gone after redemption
	if _, err := server.Storage.LoadAuthorize("9999"); err != ErrNotFound {
		t.Fatalf("Redeemed code should have been removed, err=%v", err)
	}

	// replaying the same code must be rejected and must not issue new tokens
	replay := server.NewResponse()
	if ar := server.HandleAccessRequest(replay, newAuthorizationCodeRequest("9999")); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(replay, newAuthorizationCodeRequest("9999"), ar)
	}
	if !replay.IsError || replay.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Replayed code must be rejected with invalid_grant, got error=%v id=%s", replay.IsError, replay.ErrorId)
	}
	if _, ok := replay.Output["access_token"]; ok {
		t.Fatalf("Replayed code must not produce an access token")
	}
}

func TestAccessAuthorizationCodeConcurrentSingleRedemption(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	storage := NewTestingStorage()
	storage.SaveAuthorize(&AuthorizeData{
		Client:      storage.clients["1234"],
		Code:        "concurrent-code",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	})
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	const attempts = 20
	var wg sync.WaitGroup
	results := make(chan bool, attempts)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			resp := server.NewResponse()
			if ar := server.HandleAccessRequest(resp, newAuthorizationCodeRequest("concurrent-code")); ar != nil {
				ar.Authorized = true
				server.FinishAccessRequest(resp, newAuthorizationCodeRequest("concurrent-code"), ar)
			}
			results <- !resp.IsError
		}()
	}
	wg.Wait()
	close(results)

	succeeded := 0
	for ok := range results {
		if ok {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("Exactly one concurrent exchange must succeed, got %d", succeeded)
	}

	accessCount := 0
	for _, data := range storage.access {
		if data.AuthorizeData != nil && data.AuthorizeData.Code == "concurrent-code" {
			accessCount++
		}
	}
	if accessCount != 1 {
		t.Fatalf("Exactly one access token set must exist for the code, got %d", accessCount)
	}
}

type saveAccessFailingStorage struct {
	*TestingStorage
	failOnce sync.Once
	failed   chan struct{}
}

func (s *saveAccessFailingStorage) Clone() Storage {
	return s
}

func (s *saveAccessFailingStorage) Close() {
	s.TestingStorage.Close()
}

func (s *saveAccessFailingStorage) GetClient(id string) (Client, error) {
	return s.TestingStorage.GetClient(id)
}

func (s *saveAccessFailingStorage) SaveAuthorize(data *AuthorizeData) error {
	return s.TestingStorage.SaveAuthorize(data)
}

func (s *saveAccessFailingStorage) LoadAuthorize(code string) (*AuthorizeData, error) {
	return s.TestingStorage.LoadAuthorize(code)
}

func (s *saveAccessFailingStorage) RemoveAuthorize(code string) error {
	return s.TestingStorage.RemoveAuthorize(code)
}

func (s *saveAccessFailingStorage) SaveAccess(data *AccessData) error {
	fail := false
	s.failOnce.Do(func() {
		fail = true
		close(s.failed)
	})
	if fail {
		return errors.New("simulated storage outage")
	}
	return s.TestingStorage.SaveAccess(data)
}

func (s *saveAccessFailingStorage) LoadAccess(code string) (*AccessData, error) {
	return s.TestingStorage.LoadAccess(code)
}

func (s *saveAccessFailingStorage) RemoveAccess(code string) error {
	return s.TestingStorage.RemoveAccess(code)
}

func (s *saveAccessFailingStorage) LoadRefresh(code string) (*AccessData, error) {
	return s.TestingStorage.LoadRefresh(code)
}

func (s *saveAccessFailingStorage) RemoveRefresh(code string) error {
	return s.TestingStorage.RemoveRefresh(code)
}

func TestAccessAuthorizationCodeReplayWindowAfterTokenFailure(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	storage := &saveAccessFailingStorage{
		TestingStorage: NewTestingStorage(),
		failed:         make(chan struct{}),
	}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// first attempt: the code is claimed, then token storage fails
	failedResp := server.NewResponse()
	if ar := server.HandleAccessRequest(failedResp, newAuthorizationCodeRequest("9999")); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(failedResp, newAuthorizationCodeRequest("9999"), ar)
	}
	<-storage.failed
	if !failedResp.IsError || failedResp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("First attempt should fail with server_error, got error=%v id=%s", failedResp.IsError, failedResp.ErrorId)
	}

	// the compensation restores the code, so one retry within its lifetime works
	if _, err := storage.LoadAuthorize("9999"); err != nil {
		t.Fatalf("Code should be restored for the replay window, err=%v", err)
	}

	retry := server.NewResponse()
	if ar := server.HandleAccessRequest(retry, newAuthorizationCodeRequest("9999")); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(retry, newAuthorizationCodeRequest("9999"), ar)
	}
	if retry.IsError {
		t.Fatalf("Retry within the replay window should succeed: %v", retry.InternalError)
	}

	// after the successful retry the code is consumed again
	secondReplay := server.NewResponse()
	if ar := server.HandleAccessRequest(secondReplay, newAuthorizationCodeRequest("9999")); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(secondReplay, newAuthorizationCodeRequest("9999"), ar)
	}
	if !secondReplay.IsError || secondReplay.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Second replay must be rejected, got error=%v id=%s", secondReplay.IsError, secondReplay.ErrorId)
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
