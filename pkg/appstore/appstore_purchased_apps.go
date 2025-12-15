package appstore

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/majd/ipatool/v2/pkg/http"
	"howett.net/plist"
)

type PurchasedAppsInput struct {
	Account Account
	Limit   int // Maximum number of apps to return (0 = all)
}

type PurchasedAppsOutput struct {
	Apps []PurchasedApp
}

type PurchasedApp struct {
	ID       int64  `json:"trackId"`
	BundleID string `json:"bundleId"`
	Name     string `json:"trackName"`
	Version  string `json:"version"`
}

type purchasedAppsResult struct {
	FailureType     string                   `plist:"failureType,omitempty"`
	CustomerMessage string                   `plist:"customerMessage,omitempty"`
	Items           []purchasedAppItemResult `plist:"songList,omitempty"`
}

type purchasedAppItemResult struct {
	Metadata map[string]interface{} `plist:"metadata,omitempty"`
}

func (t *appstore) PurchasedApps(input PurchasedAppsInput) (PurchasedAppsOutput, error) {
	macAddr, err := t.machine.MacAddress()
	if err != nil {
		return PurchasedAppsOutput{}, fmt.Errorf("failed to get mac address: %w", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")

	req := t.purchasedAppsRequest(input.Account, guid)

	// We'll use a temporary workaround - call the httpClient with proper handling
	reqHTTP, err := t.httpClient.NewRequest(req.Method, req.URL, nil)
	if err != nil {
		return PurchasedAppsOutput{}, fmt.Errorf("failed to create request: %w", err)
	}

	for key, val := range req.Headers {
		reqHTTP.Header.Set(key, val)
	}

	// Add payload
	if req.Payload != nil {
		buffer := new(bytes.Buffer)
		if xmlPayload, ok := req.Payload.(*http.XMLPayload); ok {
			err := plist.NewEncoder(buffer).Encode(xmlPayload.Content)
			if err != nil {
				return PurchasedAppsOutput{}, fmt.Errorf("failed to encode payload: %w", err)
			}
			reqHTTP.Body = io.NopCloser(buffer)
			reqHTTP.ContentLength = int64(buffer.Len())
		}
	}

	res, err := t.httpClient.Do(reqHTTP)
	if err != nil {
		return PurchasedAppsOutput{}, fmt.Errorf("failed to send http request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return PurchasedAppsOutput{}, fmt.Errorf("failed to read response: %w", err)
	}

	// Debug: print first 200 chars of response
	fmt.Printf("[debug] Response status: %d\n", res.StatusCode)
	fmt.Printf("[debug] Response headers: %v\n", res.Header)
	if len(body) > 200 {
		fmt.Printf("[debug] Response body (first 200 chars): %s\n", string(body[:200]))
	} else {
		fmt.Printf("[debug] Response body: %s\n", string(body))
	}

	var result purchasedAppsResult
	_, err = plist.Unmarshal(body, &result)
	if err != nil {
		return PurchasedAppsOutput{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if result.FailureType == FailureTypePasswordTokenExpired {
		return PurchasedAppsOutput{}, ErrPasswordTokenExpired
	}

	if result.FailureType != "" && result.CustomerMessage != "" {
		return PurchasedAppsOutput{}, fmt.Errorf("received error: %s", result.CustomerMessage)
	}

	if result.FailureType != "" {
		return PurchasedAppsOutput{}, fmt.Errorf("received error: %s", result.FailureType)
	}

	apps := make([]PurchasedApp, 0)
	for _, item := range result.Items {
		app := PurchasedApp{}

		if id, ok := item.Metadata["itemId"].(uint64); ok {
			app.ID = int64(id)
		}
		if bundleID, ok := item.Metadata["softwareVersionBundleId"].(string); ok {
			app.BundleID = bundleID
		}
		if name, ok := item.Metadata["itemName"].(string); ok {
			app.Name = name
		}
		if version, ok := item.Metadata["bundleShortVersionString"].(string); ok {
			app.Version = version
		}

		if app.ID > 0 {
			apps = append(apps, app)

			if input.Limit > 0 && len(apps) >= input.Limit {
				break
			}
		}
	}

	return PurchasedAppsOutput{
		Apps: apps,
	}, nil
}

func (t *appstore) purchasedAppsRequest(acc Account, guid string) http.Request {
	host := fmt.Sprintf("%s-%s", PrivateAppStoreAPIDomainPrefixWithoutAuthCode, PrivateAppStoreAPIDomain)

	payload := map[string]interface{}{
		"guid": guid,
	}

	return http.Request{
		URL:            fmt.Sprintf("https://%s/WebObjects/MZFinance.woa/wa/purchaseHistory?guid=%s", host, guid),
		Method:         http.MethodPOST,
		ResponseFormat: http.ResponseFormatXML,
		Headers: map[string]string{
			"Content-Type": "application/x-apple-plist",
			"iCloud-DSID":  acc.DirectoryServicesID,
			"X-Dsid":       acc.DirectoryServicesID,
		},
		Payload: &http.XMLPayload{
			Content: payload,
		},
	}
}
