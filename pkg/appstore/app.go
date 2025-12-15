package appstore

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
)

type App struct {
	ID       int64  `json:"trackId,omitempty"`
	BundleID string `json:"bundleId,omitempty"`
	Name     string `json:"trackName,omitempty"`
	Version  string `json:"version,omitempty"`
	Artwork  string `json:"artworkUrl512,omitempty"`
	Size     int64  `json:"fileSizeBytes,string,omitempty"`
	// FileSize is a human-readable representation of Size in MB (e.g. "12.3 MB").
	FileSize  string  `json:"fileSize,omitempty"`
	Price     float64 `json:"price,omitempty"`
	Purchased bool    `json:"purchased,omitempty"`
}

type VersionHistoryInfo struct {
	App                App
	LatestVersion      string
	VersionIdentifiers []string
}

type VersionDetails struct {
	VersionID     string
	VersionString string
	Success       bool
	Error         string
}

type Apps []App

func (apps Apps) MarshalZerologArray(a *zerolog.Array) {
	for _, app := range apps {
		a.Object(app)
	}
}

func (a App) MarshalZerologObject(event *zerolog.Event) {
	event.
		Int64("id", a.ID).
		Str("bundleID", a.BundleID).
		Str("name", a.Name).
		Str("version", a.Version).
		Str("artwork", a.Artwork).
		Int64("size", a.Size).
		Str("fileSize", a.FileSize).
		Float64("price", a.Price).
		Bool("purchased", a.Purchased)
}

// UnmarshalJSON implements custom unmarshalling to prefer whichever artwork
// URL is present in the API response. The iTunes/API responses can include
// different artwork keys (artworkUrl512, artworkUrl100, artworkUrl60, ...).
// This method fills the exported Artwork field from the first available key.
func (a *App) UnmarshalJSON(data []byte) error {
	// Alias to avoid infinite recursion when unmarshalling into App
	type alias App

	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Try to read multiple possible artwork keys
	var art struct {
		Artwork512 string `json:"artworkUrl512"`
		Artwork100 string `json:"artworkUrl100"`
		Artwork60  string `json:"artworkUrl60"`
	}

	_ = json.Unmarshal(data, &art)

	*(*alias)(a) = tmp

	if art.Artwork512 != "" {
		a.Artwork = art.Artwork512
	} else if art.Artwork100 != "" {
		a.Artwork = art.Artwork100
	} else if art.Artwork60 != "" {
		a.Artwork = art.Artwork60
	}

	// Compute human-readable file size in MB (one decimal place) if Size is present.
	if a.Size > 0 {
		mb := float64(a.Size) / 1024.0 / 1024.0
		a.FileSize = fmt.Sprintf("%.1f MB", mb)
	} else {
		a.FileSize = ""
	}

	return nil
}
