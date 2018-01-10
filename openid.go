package quickbooks

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
)

// OpenIDCOnfig struct defines the OpenID configuration document
// for QuickBooks. It needs to be retrieved as early as possible.
type OpenIDConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	jwks                              *JWKS
}

// Address struct defines the address fields returned from
// the Open ID user info response from QuickBooks
type Address struct {
	StreetAddress string `json:"streetAddress"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postalCode"`
	Country       string `json:"country"`
}

// UserInfo struct defines the user fields returned from
// the Open ID user info response from QuickBooks.
type UserInfo struct {
	Sub                 string  `json:"sub"`
	Email               string  `json:"email"`
	EmailVerified       bool    `json:"emailVerified"`
	GivenName           string  `json:"givenName"`
	FamilyName          string  `json:"familyName"`
	PhoneNumber         string  `json:"phoneNumber"`
	PhoneNumberVerified bool    `json:"phoneNumberVerified"`
	Address             Address `json:"address"`
}

// JWKS struct defines the JSON Web Key Set used for verifying Open ID
// tokens from QuickBooks.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK struct defines a JSON Web Key used for verifying Open ID tokens
// from QuickBooks.
type JWK struct {
	KTY string `json:"kty"`
	E   string `json:"e"`
	USE string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
}

// PublicKey constructs an RSA Public Key from a JWK struct. This
// can be used to verify an Open ID token signature.
func (j *JWK) PublicKey() (*rsa.PublicKey, error) {

	modulus, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	n := big.NewInt(0)
	n.SetBytes(modulus)

	exponent, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	var b []byte = exponent
	if len(exponent) < 8 {
		b = make([]byte, 8-len(exponent), 8)
		b = append(b, exponent...)
	}
	reader := bytes.NewReader(b)
	var e uint64
	err = binary.Read(reader, binary.BigEndian, &e)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// FetchJWKS retrieves the JSON Web Key Set from QuickBooks for use
// in verifying Open ID tokens.
func (c *OpenIDConfig) FetchJWKS() error {
	request, err := http.NewRequest("GET", c.JWKSURI, nil)
	if err != nil {
		return err
	}
	request.Header.Set("accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var jwks = new(JWKS)
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return err
	}
	c.jwks = jwks
	return nil
}

// UserInfo returns information the QuickBooks user. The OpenIDConfig parameter
// is needed to provide the correct user info endpoint defined in the Open ID configuration
// document for QuickBooks.
func (c *Config) UserInfo(bearer *Bearer) (*UserInfo, error) {
	b, err := bearer.Request(c.openID.UserinfoEndpoint, http.MethodGet)
	if err != nil {
		return nil, err
	}

	user := new(UserInfo)
	err = json.Unmarshal(b, &user)
	return user, err
}
