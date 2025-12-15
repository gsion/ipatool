package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

type VersionMetadataResult struct {
	ExternalVersionID string    `json:"externalVersionID"`
	DisplayVersion    string    `json:"displayVersion"`
	ReleaseDate       time.Time `json:"releaseDate"`
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler
func (v VersionMetadataResult) MarshalZerologObject(e *zerolog.Event) {
	e.Str("externalVersionID", v.ExternalVersionID).
		Str("displayVersion", v.DisplayVersion).
		Time("releaseDate", v.ReleaseDate)
}

// MarshalZerologArray implements zerolog.LogArrayMarshaler for []VersionMetadataResult
type VersionMetadataResults []VersionMetadataResult

func (v VersionMetadataResults) MarshalZerologArray(arr *zerolog.Array) {
	for _, result := range v {
		arr.Object(result)
	}
}

// nolint:wrapcheck
func getVersionMetadataCmd() *cobra.Command {
	var (
		appID             int64
		bundleID          string
		externalVersionID string
	)

	cmd := &cobra.Command{
		Use:   "get-version-metadata",
		Short: "Retrieves the metadata for a specific version of an app",
		RunE: func(cmd *cobra.Command, args []string) error {
			if appID == 0 && bundleID == "" {
				return errors.New("either the app ID or the bundle identifier must be specified")
			}

			// Parse external version IDs (comma-separated)
			versionIDs := strings.Split(externalVersionID, ",")
			var trimmedVersionIDs []string
			for _, id := range versionIDs {
				trimmed := strings.TrimSpace(id)
				if trimmed != "" {
					trimmedVersionIDs = append(trimmedVersionIDs, trimmed)
				}
			}

			if len(trimmedVersionIDs) == 0 {
				return errors.New("at least one external version ID must be specified")
			}

			var lastErr error
			var acc appstore.Account

			return retry.Do(func() error {
				infoResult, err := dependencies.AppStore.AccountInfo()
				if err != nil {
					return err
				}

				acc = infoResult.Account

				if errors.Is(lastErr, appstore.ErrPasswordTokenExpired) {
					loginResult, err := dependencies.AppStore.Login(appstore.LoginInput{Email: acc.Email, Password: acc.Password})
					if err != nil {
						return err
					}

					acc = loginResult.Account
				}

				app := appstore.App{ID: appID}
				if bundleID != "" {
					lookupResult, err := dependencies.AppStore.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID})
					if err != nil {
						return err
					}

					app = lookupResult.App
				}

				// Collect metadata for all version IDs
				var results VersionMetadataResults
				for _, versionID := range trimmedVersionIDs {
					out, err := dependencies.AppStore.GetVersionMetadata(appstore.GetVersionMetadataInput{
						Account:   acc,
						App:       app,
						VersionID: versionID,
					})
					if err != nil {
						return err
					}

					results = append(results, VersionMetadataResult{
						ExternalVersionID: versionID,
						DisplayVersion:    out.DisplayVersion,
						ReleaseDate:       out.ReleaseDate,
					})
				}

				// Log all results as an array
				dependencies.Logger.Log().
					Array("versions", results).
					Bool("success", true).
					Send()

				return nil
			},
				retry.LastErrorOnly(true),
				retry.DelayType(retry.FixedDelay),
				retry.Delay(time.Millisecond),
				retry.Attempts(2),
				retry.RetryIf(func(err error) bool {
					lastErr = err

					return errors.Is(err, appstore.ErrPasswordTokenExpired)
				}),
			)
		},
	}

	cmd.Flags().Int64VarP(&appID, "app-id", "i", 0, "ID of the target iOS app (required)")
	cmd.Flags().StringVarP(&bundleID, "bundle-identifier", "b", "", "The bundle identifier of the target iOS app (overrides the app ID)")
	cmd.Flags().StringVar(&externalVersionID, "external-version-id", "", "External version identifier(s) of the target iOS app. Supports comma-separated values to fetch metadata for multiple versions (required)")

	_ = cmd.MarkFlagRequired("external-version-id")

	return cmd
}
