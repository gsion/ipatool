package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/templates"
	"github.com/spf13/cobra"
)

// Passphrase request/response channels for WebSocket communication
type PassphraseRequest struct {
	ResponseChan chan string
}

var (
	passphraseRequestChan chan PassphraseRequest
	passphraseRequestOnce sync.Once
)

// nolint:wrapcheck
func serverCmd() *cobra.Command {
	var (
		port int
		host string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start a web server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set server mode flag to prevent interactive password prompts
			isServerMode = true

			// Load passphrase from file if exists (for server restarts)
			if data, err := os.ReadFile("passphrase.txt"); err == nil {
				keychainPassphrase = strings.TrimSpace(string(data))
				dependencies.Logger.Log().Msg("🔐 Loaded keychain passphrase from file on startup")
			}

			addr := fmt.Sprintf("%s:%d", host, port)

			// Parse templates
			tmpl, err := template.ParseFS(templates.FS, "*.html")
			if err != nil {
				return fmt.Errorf("failed to parse templates: %w", err)
			}

			// Static pages
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.NotFound(w, r)
					return
				}
				// Redirect to main page
				http.Redirect(w, r, "/main", http.StatusFound)
			})

			http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				tmpl.ExecuteTemplate(w, "login.html", nil)
			})

			http.HandleFunc("/main", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				tmpl.ExecuteTemplate(w, "main.html", nil)
			})

			// API endpoints
			http.HandleFunc("/ws/login/", handleLogin)
			http.HandleFunc("/ws/download/", handleDownload)
			http.HandleFunc("/terminal/login", handleLogin)
			http.HandleFunc("/terminal/check-login", handleCheckLogin)
			http.HandleFunc("/terminal/logout", handleLogout)
			http.HandleFunc("/terminal/search", handleSearch)
			http.HandleFunc("/terminal/list-versions", handleListVersions)
			http.HandleFunc("/terminal/purchase", handlePurchase)
			http.HandleFunc("/terminal/ipa/list", handleIPAList)
			http.HandleFunc("/terminal/ipa/delete", handleIPADelete)
			http.HandleFunc("/terminal/ipa/download", handleIPADownload)

			dependencies.Logger.Log().
				Str("address", addr).
				Msg("Starting web server")

			fmt.Printf("\n🚀 Server running at http://%s\n", addr)
			fmt.Printf("📱 Login page: http://%s/login\n", addr)
			fmt.Printf("🔍 Main page: http://%s/main\n\n", addr)

			if err := http.ListenAndServe(addr, nil); err != nil {
				return fmt.Errorf("failed to start server: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 9527, "Port to listen on")
	cmd.Flags().StringVar(&host, "host", "0.0.0.0", "Host to bind to")

	return cmd
}

// Response structures
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func respondJSON(w http.ResponseWriter, statusCode int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

func handleCheckLogin(w http.ResponseWriter, r *http.Request) {
	accountInfo, err := dependencies.AppStore.AccountInfo()

	if err != nil {
		respondJSON(w, http.StatusOK, Response{
			Success: false,
			Data: map[string]interface{}{
				"logged_in": false,
			},
		})
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"logged_in":           true,
			"name":                accountInfo.Account.Name,
			"email":               accountInfo.Account.Email,
			"directoryServicesId": accountInfo.Account.DirectoryServicesID,
			"storefront":          accountInfo.Account.StoreFront,
		},
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Revoke authentication
	revokeErr := dependencies.AppStore.Revoke()
	if revokeErr != nil {
		dependencies.Logger.Log().
			Err(revokeErr).
			Msg("⚠️ Failed to revoke authentication")
	} else {
		dependencies.Logger.Log().Msg("✅ Authentication revoked")
	}

	// Clear global passphrase variable
	keychainPassphrase = ""

	// Delete passphrase file if exists
	if _, err := os.Stat("passphrase.txt"); err == nil {
		os.Remove("passphrase.txt")
		dependencies.Logger.Log().Msg("🗑️ Deleted passphrase.txt and cleared passphrase from memory")
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Logged out successfully",
	})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	accountInfo, err := dependencies.AppStore.AccountInfo()
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Please login first",
		})
		return
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	result, err := dependencies.AppStore.Search(appstore.SearchInput{
		Account: accountInfo.Account,
		Term:    query,
		Limit:   int64(limit),
	})

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Search failed: %v", err),
		})
		return
	}

	var apps []map[string]interface{}
	for _, app := range result.Results {
		apps = append(apps, map[string]interface{}{
			"id":        app.ID,
			"bundleID":  app.BundleID,
			"name":      app.Name,
			"version":   app.Version,
			"price":     app.Price,
			"purchased": app.Purchased,
			"artwork":   app.Artwork,
			"fileSize":  app.FileSize,
		})
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    apps,
	})
}

func handleListVersions(w http.ResponseWriter, r *http.Request) {
	accountInfo, err := dependencies.AppStore.AccountInfo()
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Please login first",
		})
		return
	}

	bundleID := r.URL.Query().Get("bundle_id")

	if bundleID == "" {
		respondJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "bundle_id is required",
		})
		return
	}

	// Parse pagination parameters
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page := 1
	limit := 10 // Default limit

	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50 {
			limit = l
		}
	}

	// Lookup app by bundle ID
	lookupResult, err := dependencies.AppStore.Lookup(appstore.LookupInput{
		Account:  accountInfo.Account,
		BundleID: bundleID,
	})
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Lookup failed: %v", err),
		})
		return
	}
	app := lookupResult.App

	result, err := dependencies.AppStore.ListVersions(appstore.ListVersionsInput{
		Account: accountInfo.Account,
		App:     app,
	})

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("List versions failed: %v", err),
		})
		return
	}

	// Calculate pagination
	allVersionIDs := result.ExternalVersionIdentifiers
	// Reverse the version list so newest versions appear first
	for i, j := 0, len(allVersionIDs)-1; i < j; i, j = i+1, j-1 {
		allVersionIDs[i], allVersionIDs[j] = allVersionIDs[j], allVersionIDs[i]
	}
	total := len(allVersionIDs)
	startIdx := (page - 1) * limit
	endIdx := startIdx + limit

	if startIdx >= total {
		respondJSON(w, http.StatusOK, Response{
			Success: true,
			Data: map[string]interface{}{
				"versions": []map[string]interface{}{},
				"latest":   result.LatestExternalVersionID,
			},
		})
		return
	}

	if endIdx > total {
		endIdx = total
	}

	// Get only the versions for current page
	pageVersionIDs := allVersionIDs[startIdx:endIdx]

	// Get detailed metadata for each version in the current page
	var versions []map[string]interface{}
	for _, versionID := range pageVersionIDs {
		metadata, err := dependencies.AppStore.GetVersionMetadata(appstore.GetVersionMetadataInput{
			Account:   accountInfo.Account,
			App:       app,
			VersionID: versionID,
		})

		if err != nil {
			// If metadata fetch fails, just use the version ID
			versions = append(versions, map[string]interface{}{
				"externalVersionID": versionID,
				"version":           versionID,
			})
			continue
		}

		// Format file size for display
		fileSizeDisplay := metadata.FileSize
		if fileSizeDisplay == "" && metadata.FileSizeBytes > 0 {
			mb := float64(metadata.FileSizeBytes) / (1024.0 * 1024.0)
			fileSizeDisplay = fmt.Sprintf("%.2f MB", mb)
		}

		versions = append(versions, map[string]interface{}{
			"externalVersionID": versionID,
			"displayVersion":    metadata.DisplayVersion,
			"releaseDate":       metadata.ReleaseDate,
			"fileSizeBytes":     metadata.FileSizeBytes,
			"fileSize":          fileSizeDisplay,
		})
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"versions": versions,
			"latest":   result.LatestExternalVersionID,
			"pagination": map[string]interface{}{
				"page":        page,
				"limit":       limit,
				"total":       total,
				"has_next":    endIdx < total,
				"has_prev":    page > 1,
				"total_pages": (total + limit - 1) / limit,
			},
		},
	})
}

func handlePurchase(w http.ResponseWriter, r *http.Request) {
	accountInfo, err := dependencies.AppStore.AccountInfo()
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Message: "Please login first",
		})
		return
	}

	var req struct {
		BundleID  string `json:"bundleID"`
		BundleID2 string `json:"bundle_id"` // Support snake_case
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	// Use snake_case if camelCase is empty
	bundleID := req.BundleID
	if bundleID == "" {
		bundleID = req.BundleID2
	}

	if bundleID == "" {
		respondJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "bundle_id is required",
		})
		return
	}

	// Lookup app by bundle ID
	lookupResult, err := dependencies.AppStore.Lookup(appstore.LookupInput{
		Account:  accountInfo.Account,
		BundleID: bundleID,
	})
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Lookup failed: %v", err),
		})
		return
	}
	app := lookupResult.App

	err = dependencies.AppStore.Purchase(appstore.PurchaseInput{
		Account: accountInfo.Account,
		App:     app,
	})

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Purchase failed: %v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Purchase successful",
	})
}

func handleIPAList(w http.ResponseWriter, r *http.Request) {
	appStoreDir := "appstore"

	// Check if directory exists
	if _, err := os.Stat(appStoreDir); os.IsNotExist(err) {
		respondJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    []interface{}{},
		})
		return
	}

	// Read all bundle directories
	bundleDirs, err := os.ReadDir(appStoreDir)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Failed to read directory: %v", err),
		})
		return
	}

	type FileInfo struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Size        int64  `json:"size"`
		SizeDisplay string `json:"size_display"`
		MTime       string `json:"mtime_display"`
	}

	type BundleInfo struct {
		BundleID         string     `json:"bundle_id"`
		Files            []FileInfo `json:"files"`
		FileCount        int        `json:"file_count"`
		TotalSize        int64      `json:"total_size"`
		TotalSizeDisplay string     `json:"total_size_display"`
	}

	var bundles []BundleInfo

	for _, bundleDir := range bundleDirs {
		if !bundleDir.IsDir() {
			continue
		}

		bundleID := bundleDir.Name()
		bundlePath := filepath.Join(appStoreDir, bundleID)

		// Read IPA files in this bundle
		ipaFiles, err := os.ReadDir(bundlePath)
		if err != nil {
			continue
		}

		var files []FileInfo
		var totalSize int64

		for _, ipaFile := range ipaFiles {
			if ipaFile.IsDir() || filepath.Ext(ipaFile.Name()) != ".ipa" {
				continue
			}

			filePath := filepath.Join(bundlePath, ipaFile.Name())
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			files = append(files, FileInfo{
				Name:        ipaFile.Name(),
				Path:        filePath,
				Size:        fileInfo.Size(),
				SizeDisplay: formatFileSize(fileInfo.Size()),
				MTime:       fileInfo.ModTime().Format("2006-01-02 15:04:05"),
			})
			totalSize += fileInfo.Size()
		}

		if len(files) > 0 {
			bundles = append(bundles, BundleInfo{
				BundleID:         bundleID,
				Files:            files,
				FileCount:        len(files),
				TotalSize:        totalSize,
				TotalSizeDisplay: formatFileSize(totalSize),
			})
		}
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    bundles,
	})
}

func handleIPADelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request body",
		})
		return
	}

	if req.Path == "" {
		respondJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Path is required",
		})
		return
	}

	// Security: ensure path is within appstore directory
	appStoreDir := "appstore"
	absAppStoreDir, _ := filepath.Abs(appStoreDir)
	absPath, _ := filepath.Abs(req.Path)

	if !strings.HasPrefix(absPath, absAppStoreDir) {
	}

	// Delete the file
	if err := os.Remove(req.Path); err != nil {
		respondJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: fmt.Sprintf("Failed to delete file: %v", err),
		})
		return
	}

	// Try to remove empty parent directory
	dir := filepath.Dir(req.Path)
	if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
		os.Remove(dir)
	}

	respondJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "File deleted successfully",
	})
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		dependencies.Logger.Log().Err(err).Msg("Failed to upgrade websocket")
		return
	}
	defer conn.Close()

	// Read first message - parse directly into login data structure
	var loginData struct {
		Type               string `json:"type"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		KeychainPassphrase string `json:"keychain_passphrase"`
	}

	if err := conn.ReadJSON(&loginData); err != nil {
		sendWSError(conn, "Invalid message format")
		return
	}

	if loginData.Username == "" || loginData.Password == "" {
		sendWSError(conn, "Username and password are required")
		return
	}

	// Send login started message
	sendWSMessage(conn, "login_started", "Starting login process")
	sendWSMessage(conn, "output", "Attempting to login...")

	dependencies.Logger.Log().
		Str("username", loginData.Username).
		Bool("has_passphrase", keychainPassphrase != "").
		Msg("🔐 Login attempt started")

	// Attempt login
	result, err := dependencies.AppStore.Login(appstore.LoginInput{
		Email:    loginData.Username,
		Password: loginData.Password,
		AuthCode: "",
	})

	if err != nil {
		dependencies.Logger.Log().
			Err(err).
			Str("username", loginData.Username).
			Msg("❌ First login attempt failed")

		errMsg := err.Error()

		// Debug: log the actual error message to see what we're checking
		dependencies.Logger.Log().
			Str("error_message", errMsg).
			Str("username", loginData.Username).
			Msg("🔍 Debug: Actual error message received")

		// Handle 2FA if required
		if errors.Is(err, appstore.ErrAuthCodeRequired) {
			dependencies.Logger.Log().
				Str("username", loginData.Username).
				Msg("🔑 2FA code required")

			sendWSMessage(conn, "output", "2FA code required. Please check your device.")
			sendWSMessage(conn, "need_input", "Enter 2FA code:")

			// Wait for 2FA code from client
			var inputMsg WSMessage
			readErr := conn.ReadJSON(&inputMsg)
			if readErr == nil {
				var authCode string
				if code, ok := inputMsg.Data.(string); ok {
					authCode = code
				} else if dataMap, ok := inputMsg.Data.(map[string]interface{}); ok {
					if code, ok := dataMap["input"].(string); ok {
						authCode = code
					}
				}

				if authCode != "" {
					dependencies.Logger.Log().
						Str("username", loginData.Username).
						Str("2fa_code", authCode).
						Msg("🔄 Retrying login with 2FA code")

					sendWSMessage(conn, "output", "Retrying login with 2FA code...")
					// Retry with password + 2FA code
					result, err = dependencies.AppStore.Login(appstore.LoginInput{
						Email:    loginData.Username,
						Password: loginData.Password + authCode,
						AuthCode: "",
					})

					if err != nil {
						dependencies.Logger.Log().
							Err(err).
							Str("username", loginData.Username).
							Msg("❌ Login with 2FA failed")
						errMsg = err.Error() // Update error message for next check
					} else {
						dependencies.Logger.Log().
							Str("username", loginData.Username).
							Msg("✅ Login with 2FA succeeded")
					}
				}
			}
		}

		// Handle passphrase if required (can happen after 2FA or on first attempt)
		if err != nil && (strings.Contains(errMsg, "passphrase required") || strings.Contains(errMsg, "enter passphrase to unlock")) {
			// Need keychain passphrase
			dependencies.Logger.Log().
				Str("username", loginData.Username).
				Msg("🔐 Keychain passphrase required")

			// Send need_passphrase message to trigger UI
			sendWSMessage(conn, "output", "Keychain passphrase required")
			sendWSMessage(conn, "need_passphrase", "Please enter keychain passphrase")

			// Wait for passphrase from client
			var passphraseMsg WSMessage
			readErr := conn.ReadJSON(&passphraseMsg)
			if readErr == nil {
				var passphrase string
				if pp, ok := passphraseMsg.Data.(string); ok {
					passphrase = pp
				} else if dataMap, ok := passphraseMsg.Data.(map[string]interface{}); ok {
					if pp, ok := dataMap["passphrase"].(string); ok {
						passphrase = pp
					} else if pp, ok := dataMap["input"].(string); ok {
						passphrase = pp
					}
				}

				if passphrase != "" {
					dependencies.Logger.Log().
						Str("username", loginData.Username).
						Str("passphrase_length", fmt.Sprintf("%d", len(passphrase))).
						Msg("🔄 Retrying login with passphrase")

					// Save passphrase to memory and file
					keychainPassphrase = strings.TrimSpace(passphrase)
					os.WriteFile("passphrase.txt", []byte(keychainPassphrase), 0600)

					sendWSMessage(conn, "output", "Retrying login with passphrase...")
					// Retry login with the original credentials (passphrase now in memory)
					result, err = dependencies.AppStore.Login(appstore.LoginInput{
						Email:    loginData.Username,
						Password: loginData.Password,
						AuthCode: "",
					})

					if err != nil {
						dependencies.Logger.Log().
							Err(err).
							Str("username", loginData.Username).
							Msg("❌ Login with passphrase failed")
					} else {
						dependencies.Logger.Log().
							Str("username", loginData.Username).
							Msg("✅ Login with passphrase succeeded")
					}
				} else {
					dependencies.Logger.Log().
						Str("username", loginData.Username).
						Msg("⚠️ Passphrase not provided or read error")
				}
			} else {
				dependencies.Logger.Log().
					Err(readErr).
					Str("username", loginData.Username).
					Msg("⚠️ Failed to read passphrase from WebSocket")
			}
		}

		// If still error after all retry attempts
		if err != nil {
			errMsg := fmt.Sprintf("Login failed: %v", err)
			dependencies.Logger.Log().
				Str("username", loginData.Username).
				Str("error", errMsg).
				Msg("❌ Login failed - sending error to client")

			sendWSMessage(conn, "output", errMsg)
			conn.WriteJSON(map[string]interface{}{
				"type":    "login_failed",
				"message": errMsg,
				"data":    errMsg,
			})
			return
		}
	} else {
		dependencies.Logger.Log().
			Str("username", loginData.Username).
			Str("name", result.Account.Name).
			Msg("✅ First login attempt succeeded")
	}

	// Login succeeded, account is saved in keychain by ipatool
	dependencies.Logger.Log().
		Str("name", result.Account.Name).
		Str("email", result.Account.Email).
		Str("dsid", result.Account.DirectoryServicesID).
		Str("storefront", result.Account.StoreFront).
		Msg("✅ Login successful - session saved")

	// Send success messages
	sendWSMessage(conn, "output", fmt.Sprintf("Successfully logged in as %s", result.Account.Name))
	conn.WriteJSON(map[string]interface{}{
		"type":    "login_success",
		"message": fmt.Sprintf("Successfully logged in as %s", result.Account.Name),
		"data": map[string]interface{}{
			"name":                result.Account.Name,
			"email":               result.Account.Email,
			"directoryServicesId": result.Account.DirectoryServicesID,
			"storefront":          result.Account.StoreFront,
		},
	})
}

func sendWSMessage(conn *websocket.Conn, msgType string, data interface{}) {
	conn.WriteJSON(WSMessage{
		Type: msgType,
		Data: data,
	})
}

func sendWSError(conn *websocket.Conn, message string) {
	sendWSMessage(conn, "error", message)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func handleIPADownload(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Path is required", http.StatusBadRequest)
		return
	}

	// Security: ensure path is within appstore directory
	appStoreDir := "appstore"
	absAppStoreDir, _ := filepath.Abs(appStoreDir)
	absPath, _ := filepath.Abs(filePath)

	if !strings.HasPrefix(absPath, absAppStoreDir) {
		http.Error(w, "Invalid path", http.StatusForbidden)
		return
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filePath)))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// Stream file to response
	io.Copy(w, file)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		dependencies.Logger.Log().Err(err).Msg("Failed to upgrade websocket")
		return
	}
	defer conn.Close()

	accountInfo, err := dependencies.AppStore.AccountInfo()
	if err != nil {
		sendWSError(conn, "Please login first")
		return
	}

	// Read download request
	var msg struct {
		Type           string `json:"type"`
		BundleID       string `json:"bundle_id"`
		VersionID      string `json:"version_id"`
		DisplayVersion string `json:"display_version"`
	}

	if err := conn.ReadJSON(&msg); err != nil {
		sendWSError(conn, "Invalid message format")
		return
	}

	if msg.Type != "start_download" {
		sendWSError(conn, "Invalid message type")
		return
	}

	if msg.BundleID == "" {
		sendWSError(conn, "bundle_id is required")
		return
	}

	// Send download started message
	sendWSMessage(conn, "download_started", "Starting download...")

	// Lookup app by bundle ID
	lookupResult, err := dependencies.AppStore.Lookup(appstore.LookupInput{
		Account:  accountInfo.Account,
		BundleID: msg.BundleID,
	})
	if err != nil {
		sendWSMessage(conn, "download_failed", fmt.Sprintf("Lookup failed: %v", err))
		return
	}
	app := lookupResult.App

	// Generate output path: appstore/{bundleID}/{version}.ipa
	appStoreDir := "appstore"
	bundleDir := filepath.Join(appStoreDir, msg.BundleID)

	// Create directories if they don't exist
	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		sendWSMessage(conn, "download_failed", fmt.Sprintf("Failed to create directory: %v", err))
		return
	}

	filename := fmt.Sprintf("%s.ipa", msg.DisplayVersion)
	if msg.DisplayVersion == "" {
		filename = fmt.Sprintf("%s.ipa", msg.VersionID)
	}
	outputPath := filepath.Join(bundleDir, filename)

	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil {
		sendWSMessage(conn, "download_success", map[string]interface{}{
			"message": "File already exists, no need to download",
			"path":    outputPath,
			"existed": true,
		})
		return
	}

	// Download the app
	downloadResult, err := dependencies.AppStore.Download(appstore.DownloadInput{
		Account:           accountInfo.Account,
		App:               app,
		OutputPath:        outputPath,
		ExternalVersionID: msg.VersionID,
		Progress:          nil, // We'll handle progress differently
	})

	if err != nil {
		sendWSMessage(conn, "download_failed", fmt.Sprintf("Download failed: %v", err))
		return
	}

	// Replicate SINF
	err = dependencies.AppStore.ReplicateSinf(appstore.ReplicateSinfInput{
		Sinfs:       downloadResult.Sinfs,
		PackagePath: downloadResult.DestinationPath,
	})

	if err != nil {
		sendWSMessage(conn, "download_failed", fmt.Sprintf("Failed to replicate SINF: %v", err))
		return
	}

	// Send success message
	sendWSMessage(conn, "download_success", map[string]interface{}{
		"message": "Download completed successfully",
		"path":    downloadResult.DestinationPath,
	})
}
