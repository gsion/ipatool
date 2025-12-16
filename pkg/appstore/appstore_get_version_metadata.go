package appstore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/pkg/http"
)

type GetVersionMetadataInput struct {
	Account   Account
	App       App
	VersionID string
}

// GetVersionMetadataOutput contains parsed metadata for a specific version
// as well as the raw response body for maximum inspectability.
type GetVersionMetadataOutput struct {
	DisplayVersion string                 `json:"displayVersion,omitempty"`
	ReleaseDate    time.Time              `json:"releaseDate,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	RawBody        string                 `json:"rawBody,omitempty"`
	// FileSizeBytes is the numeric size in bytes when available in metadata.
	FileSizeBytes int64 `json:"fileSizeBytes,omitempty"`
	// FileSize is a human-readable representation (MB) of FileSizeBytes.
	FileSize string `json:"fileSize,omitempty"`
}

func (t *appstore) GetVersionMetadata(input GetVersionMetadataInput) (GetVersionMetadataOutput, error) {
	macAddr, err := t.machine.MacAddress()
	if err != nil {
		return GetVersionMetadataOutput{}, fmt.Errorf("failed to get mac address: %w", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")

	req := t.getVersionMetadataRequest(input.Account, input.App, guid, input.VersionID)
	res, err := t.downloadClient.Send(req)

	if err != nil {
		return GetVersionMetadataOutput{}, fmt.Errorf("failed to send http request: %w", err)
	}

	if res.Data.FailureType == FailureTypePasswordTokenExpired {
		return GetVersionMetadataOutput{}, ErrPasswordTokenExpired
	}

	if res.Data.FailureType == FailureTypeLicenseNotFound {
		return GetVersionMetadataOutput{}, ErrLicenseRequired
	}

	if res.Data.FailureType != "" && res.Data.CustomerMessage != "" {
		return GetVersionMetadataOutput{}, NewErrorWithMetadata(fmt.Errorf("received error: %s", res.Data.CustomerMessage), res)
	}

	if res.Data.FailureType != "" {
		return GetVersionMetadataOutput{}, NewErrorWithMetadata(fmt.Errorf("received error: %s", res.Data.FailureType), res)
	}

	if len(res.Data.Items) == 0 {
		return GetVersionMetadataOutput{}, NewErrorWithMetadata(errors.New("invalid response"), res)
	}

	item := res.Data.Items[0]

	releaseDate, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", item.Metadata["releaseDate"]))
	if err != nil {
		return GetVersionMetadataOutput{}, fmt.Errorf("failed to parse release date: %w", err)
	}

	// Get file size from the download URL by sending a HEAD request
	var fileSizeBytes int64
	if item.URL != "" {
		fileSizeBytes, err = t.getFileSizeFromURL(item.URL)
		if err != nil {
			fileSizeBytes = 0
		}
	}

	fileSizeStr := ""
	if fileSizeBytes > 0 {
		mb := float64(fileSizeBytes) / 1024.0 / 1024.0
		fileSizeStr = fmt.Sprintf("%.1f MB", mb)
	}

	return GetVersionMetadataOutput{
		DisplayVersion: fmt.Sprintf("%v", item.Metadata["bundleShortVersionString"]),
		ReleaseDate:    releaseDate,
		Metadata:       item.Metadata,
		RawBody:        string(res.RawBody),
		FileSizeBytes:  fileSizeBytes,
		FileSize:       fileSizeStr,
	}, nil
}

func (t *appstore) getVersionMetadataRequest(acc Account, app App, guid string, version string) http.Request {
	host := fmt.Sprintf("%s-%s", PrivateAppStoreAPIDomainPrefixWithoutAuthCode, PrivateAppStoreAPIDomain)

	payload := map[string]interface{}{
		"creditDisplay":     "",
		"guid":              guid,
		"salableAdamId":     app.ID,
		"externalVersionId": version,
	}

	return http.Request{
		URL:            fmt.Sprintf("https://%s%s?guid=%s", host, PrivateAppStoreAPIPathDownload, guid),
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

// getFileSizeFromURL retrieves the file size by sending a HEAD request to the download URL.
func (t *appstore) getFileSizeFromURL(url string) (int64, error) {
	// Try HEAD request first
	req, err := t.httpClient.NewRequest("HEAD", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HEAD request: %w", err)
	}

	res, err := t.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send HEAD request: %w", err)
	}
	defer res.Body.Close()

	// If ContentLength is available, return it
	if res.ContentLength > 0 {
		return res.ContentLength, nil
	}

	// Otherwise, try to get it from Content-Length header
	contentLength := res.Header.Get("Content-Length")
	if contentLength != "" {
		var size int64
		_, err := fmt.Sscanf(contentLength, "%d", &size)
		if err == nil && size > 0 {
			return size, nil
		}
	}

	return 0, nil
}
