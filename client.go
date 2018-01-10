package quickbooks

import (
	"io/ioutil"
	"net/http"
)

// Request makes an HTTP request to the QuickBooks API. If the token
// is expired, and error will be returned.
func (b *Bearer) Request(endpoint string, method string) ([]byte, error) {
	request, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+b.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(request)
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
