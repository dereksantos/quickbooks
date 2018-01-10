package quickbooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	AccountingScope = "com.intuit.quickbooks.accounting"
	PaymentsScope   = "com.intuit.quickbooks.payment"
	PhoneScope      = "phone"
	EmailScope      = "email"
	OpenIDScope     = "openid"
	AddressScope    = "address"
	ProfileScope    = "profile"
	SandboxEndpoint = "https://developer.api.intuit.com/.well-known/openid_sandbox_configuration"
)

// Config struct is used to configure an oauth implementation that
// connects with QuickBooks.
type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scope        []string
	openID       *OpenIDConfig
}

// ResponseCode struct is returned from QuickBooks via the query params
// in the callback. It should exchanged for a BearerToken before
// making API requests to QuickBooks.
type ResponseCode struct {
	Code    string
	RealmID string
	State   string
}

// Bearer struct is used to make authorized requests to the
// QuickBooks API.
type Bearer struct {
	RefreshToken           string      `json:"refresh_token"`
	AccessToken            string      `json:"access_token"`
	TokenType              string      `json:"token_type"`
	IdToken                OpenIDToken `json:"id_token"`
	ExpiresIn              int64       `json:"expires_in"`
	XRefreshTokenExpiresIn int64       `json:"x_refresh_token_expires_in"`
}

// Fetch downloads the QuickBooks OpenID configuration
// document.
func (c *Config) Fetch() error {
	request, err := http.NewRequest("GET", c.Endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("accept", "application/json")

	client := new(http.Client)
	resp, err := client.Do(request)
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	c.openID = new(OpenIDConfig)
	err = json.Unmarshal(body, &c.openID)
	if err != nil {
		return err
	}

	err = c.openID.FetchJWKS()
	if err != nil {
		return err
	}

	return nil
}

// AuthURL generates the URL string for redirection to the QuickBooks
// authentication endpoint. It will build the query parameters required
// for proper integration with QuickBooks.
func (c *Config) AuthURL(state string) string {
	var u *url.URL

	u, err := url.Parse(c.openID.AuthorizationEndpoint)
	if err != nil {
		return ""
	}

	parameters := url.Values{}
	parameters.Add("client_id", c.ClientID)
	parameters.Add("response_type", "code")
	parameters.Add("scope", strings.Join(c.Scope, " "))
	parameters.Add("redirect_uri", c.RedirectURI)
	parameters.Add("state", state)
	u.RawQuery = parameters.Encode()

	return u.String()
}

// Callback handles exchanging an OAuth Code for an Access Token,
// and verifies the OpenID Token.
func (c *Config) Bearer(r *http.Request) (*Bearer, error) {
	code := Code(r)
	bearer, err := c.Exchange(code.Code)
	if err != nil {
		return nil, err
	}

	if bearer.IdToken == "" {
		return nil, errors.New("No ID token was found.")
	}

	err = c.ValidateIDToken(bearer.IdToken)
	if err != nil {
		return nil, err
	}

	return bearer, nil
}

// Code parses the authentication code from QuickBooks for a succesful
// authentication. The code must have a valid CSRF token to be accepted by this
// implementation.
func Code(r *http.Request) *ResponseCode {
	q := r.URL.Query()
	code := new(ResponseCode)
	code.Code = q.Get("code")
	code.RealmID = q.Get("realmId")
	code.State = q.Get("state")
	return code
}

// Exchange asks QuickBooks to exchange the auth code for an access token.
func (c *Config) Exchange(code string) (*Bearer, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Add("code", code)
	data.Add("redirect_uri", c.RedirectURI)

	request, err := http.NewRequest("POST", c.openID.TokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.SetBasicAuth(c.ClientID, c.ClientSecret)

	client := &http.Client{}
	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bearer := new(Bearer)
	err = json.Unmarshal(body, &bearer)
	return bearer, err
}

// Refresh gets a new access token from the QuickBooks API using an existing
// access token.
func (c *Config) Refresh(token string) (*Bearer, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Add("refresh_token", token)

	request, err := http.NewRequest("POST", c.openID.TokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.SetBasicAuth(c.ClientID, c.ClientSecret)

	client := &http.Client{}
	resp, err := client.Do(request)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bearer := new(Bearer)
	err = json.Unmarshal(body, &bearer)
	return bearer, err
}

// Revoke invalidates an existing access token.
func (c *Config) Revoke(token string) error {
	data := url.Values{}
	data.Set("token", token)

	request, err := http.NewRequest("POST", c.openID.RevocationEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.SetBasicAuth(c.ClientID, c.ClientSecret)

	client := &http.Client{}
	resp, err := client.Do(request)
	defer resp.Body.Close()
	return err
}
