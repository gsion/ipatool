package appstore

import (
	"errors"
	"fmt"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/majd/ipatool/v2/pkg/http"
)

type SearchInput struct {
	Account Account
	Term    string
	Limit   int64
}

type SearchOutput struct {
	Count   int
	Results []App
}

func (t *appstore) Search(input SearchInput) (SearchOutput, error) {
	countryCode, err := countryCodeFromStoreFront(input.Account.StoreFront)
	if err != nil {
		return SearchOutput{}, fmt.Errorf("country code is invalid: %w", err)
	}

	request := t.searchRequest(input.Term, countryCode, input.Limit)

	res, err := t.searchClient.Send(request)
	if err != nil {
		return SearchOutput{}, fmt.Errorf("request failed: %w", err)
	}

	if res.StatusCode != gohttp.StatusOK {
		return SearchOutput{}, NewErrorWithMetadata(errors.New("request failed"), res)
	}

	// Check purchase status for each app
	for i := range res.Data.Results {
		isPurchased, _ := t.checkIfPurchased(input.Account, res.Data.Results[i])
		res.Data.Results[i].Purchased = isPurchased
	}

	return SearchOutput{
		Count:   res.Data.Count,
		Results: res.Data.Results,
	}, nil
}

type searchResult struct {
	Count   int   `json:"resultCount,omitempty"`
	Results []App `json:"results,omitempty"`
}

func (t *appstore) searchRequest(term, countryCode string, limit int64) http.Request {
	return http.Request{
		URL:            t.searchURL(term, countryCode, limit),
		Method:         http.MethodGET,
		ResponseFormat: http.ResponseFormatJSON,
	}
}

func (t *appstore) searchURL(term, countryCode string, limit int64) string {
	params := url.Values{}
	params.Add("entity", "software,iPadSoftware")
	params.Add("limit", strconv.Itoa(int(limit)))
	params.Add("media", "software")
	params.Add("term", term)
	params.Add("country", countryCode)

	return fmt.Sprintf("https://%s%s?%s", iTunesAPIDomain, iTunesAPIPathSearch, params.Encode())
}

// checkIfPurchased checks if an app is already purchased by trying to get download info
func (t *appstore) checkIfPurchased(acc Account, app App) (bool, error) {
	macAddr, err := t.machine.MacAddress()
	if err != nil {
		return false, err
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")

	req := t.downloadRequest(acc, app, guid, "")

	res, err := t.downloadClient.Send(req)
	if err != nil {
		return false, err
	}

	// If license not found, app is not purchased
	if res.Data.FailureType == FailureTypeLicenseNotFound {
		return false, nil
	}

	// If we got items or no error, app is purchased
	if res.Data.FailureType == "" || len(res.Data.Items) > 0 {
		return true, nil
	}

	// For other errors, we can't determine the status
	return false, nil
}
