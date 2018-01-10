package quickbooks

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Header struct defines the fields of an OpenID JWT Header retrieved
// from QuickBooks.
type Header struct {
	ALG string `json:"alg"`
	KID string `json:"kid"`
}

// Claims struct defines the fields of an OpenID JWT Claims retrieved
// from QuickBooks.
type Claims struct {
	AUD       []string `json:"aud"`
	EXP       int64    `json:"exp"`
	IAT       int      `json:"iat"`
	ISS       string   `json:"iss"`
	REALMID   string   `json:"realmid"`
	SUB       string   `json:"sub"`
	AUTH_TIME int      `json:"auth_time"`
}

// OpenIDToken type wraps a JWT strings and allows
// for parsing and validation of the token.
type OpenIDToken string

// Value implements the valuer interface for the database/sql package.
func (t OpenIDToken) Value() (driver.Value, error) {
	return string(t), nil
}

// Scan implements the scanner interface for the database/sql package.
func (t *OpenIDToken) Scan(value interface{}) error {
	v, ok := value.(string)
	if ok {
		*t = OpenIDToken(v)
		return nil
	}

	b, ok := value.([]uint8)
	if ok {
		*t = OpenIDToken(string(b))
		return nil
	}

	return fmt.Errorf("Can't convert %T to OpenIDToken", value)
}

// parts returns a slice of strings delimited by a period in
// an OpenID Token. An error is returned if less than 3 parts
// are contained withing the token.
func (t OpenIDToken) parts() ([]string, error) {
	parts := strings.Split(string(t), ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("Malformed ID token, expected 3 parts but got %d", len(parts))
	}
	return parts, nil
}

// part returns a string component of the OpenID token split using a period.
// An error is returned if the token contains less than 3 parts or could not
// be decoded.
func (t OpenIDToken) part(index int, encoding *base64.Encoding) ([]byte, error) {
	parts, err := t.parts()
	if err != nil {
		return nil, err
	}
	return encoding.DecodeString(parts[index])
}

// Content returns the first two parts of the OpenID token as a byte slice. The first
// two parts represent the content contained within the token. In other words,
// the non-signature parts of the token.
func (t OpenIDToken) Content() ([]byte, error) {
	parts, err := t.parts()
	if err != nil {
		return nil, err
	}
	return []byte(parts[0] + "." + parts[1]), nil
}

// Digest returns a byte slice containing the SHA256 hash of the tokens
// content.
func (t OpenIDToken) Digest() ([]byte, error) {
	data, err := t.Content()
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil), nil
}

// Claims returns a Claims struct created using the encoded
// data contained with the OpenID token. An error is returned
// if decoding fails.
func (t OpenIDToken) Claims() (*Claims, error) {
	raw, err := t.part(1, base64.RawStdEncoding)
	if err != nil {
		return nil, err
	}

	claims := new(Claims)
	err = json.Unmarshal(raw, &claims)
	return claims, err
}

// Header returns a Header struct created using the encoded
// data contained with the OpenID token. An error is returned
// if decoding fails.
func (t OpenIDToken) Header() (*Header, error) {
	raw, err := t.part(0, base64.StdEncoding)
	if err != nil {
		return nil, err
	}

	header := new(Header)
	err = json.Unmarshal(raw, &header)
	return header, err
}

// Sig returns a string with the signature of the OpenID token.
// An error is returned if decoding fails.
func (t OpenIDToken) Sig() ([]byte, error) {
	return t.part(2, base64.RawURLEncoding)
}

// ValidateIDToken checks the compliance and signature of the supplied
// OpenID token. If the claims, header or signature are invalid an error
// is returned.
func (c *Config) ValidateIDToken(token OpenIDToken) error {
	claims, err := token.Claims()
	if err != nil {
		return err
	}

	if claims.ISS != c.openID.Issuer {
		return fmt.Errorf("Issuer mismatch.")
	}

	if claims.AUD[0] != c.ClientID {
		return fmt.Errorf("Audience does not match client ID.")
	}

	if (claims.EXP - time.Now().Unix()) <= 0 {
		return fmt.Errorf("Expiration timestamp has elapsed")
	}

	header, err := token.Header()
	if err != nil {
		return err
	}

	key := c.openID.jwks.Keys[0]
	if key.KID != header.KID {
		return fmt.Errorf("No keys found for the header")
	}

	digest, err := token.Digest()
	if err != nil {
		return err
	}

	sig, err := token.Sig()
	if err != nil {
		return err
	}

	pub, err := key.PublicKey()
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	if err != nil {
		return fmt.Errorf("unable to verify signature, %s", err.Error())
	}

	return nil
}
