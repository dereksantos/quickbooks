package quickbooks

import (
	"net/http"
	"testing"
)

func TestClientAuthURL(t *testing.T) {
	config := &Config{
		Endpoint:    SandboxEndpoint,
		ClientID:    "ABCD1234",
		RedirectURI: "http://localhost:8080/redirect",
		Scope:       []string{OpenIDScope, EmailScope, ProfileScope, AccountingScope},
	}

	err := config.Fetch()
	if err != nil {
		t.Error(err)
		return
	}

	url := config.AuthURL("test")
	expected := "https://appcenter.intuit.com/connect/oauth2?client_id=ABCD1234&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fredirect&response_type=code&scope=openid+email+profile+com.intuit.quickbooks.accounting&state=test"
	if url != expected {
		t.Errorf("expected %s but got %s", expected, url)
	}
}

func TestParseCode(t *testing.T) {
	url := "http://localhost:8080/qbo/callback?state=Y3NyZj0lMTAlRTAlMEUlRjElRjglRkQtJURDUzB2byVFRSU5N3klRkI1JTAwJTVDJTdDJUJFJTVDeF8lRDAlOUNIJUVGJUY0JUQwUSVCMw%3d%3d&code=Q011513658543mTiC5zKKTKUb3zPci16Z5scqMenpmvEpqRgQ9&realmId=123145934833429"
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	code := Code(r)

	expected := "Q011513658543mTiC5zKKTKUb3zPci16Z5scqMenpmvEpqRgQ9"
	if code.Code != expected {
		t.Fatalf("Expected %s but got %s", expected, code.Code)
	}

	expected = "123145934833429"
	if code.RealmID != expected {
		t.Fatalf("Expected %s but got %s", expected, code.RealmID)
	}

}
