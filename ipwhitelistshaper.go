// filename: ipwhitelistshaper.go
// Package ipwhitelistshaper provides a Traefik middleware for dynamic IP whitelist management
package ipwhitelistshaper

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config defines the plugin configuration.
type Config struct {
	ExcludedIPs                []string `json:"excludedIPs,omitempty"`
	WhitelistedIPs             []string `json:"whitelistedIPs,omitempty"`
	IPStrategyDepth            int      `json:"ipStrategyDepth,omitempty"`
	DefaultPrivateClassSources bool     `json:"defaultPrivateClassSources,omitempty"`
	ExpirationTime             int      `json:"expirationTime,omitempty"` // Whitelist duration in seconds
	SecretKey                  string   `json:"secretKey,omitempty"`
	NotificationURL            string   `json:"notificationURL,omitempty"`
	KnockEndpoint              string   `json:"knockEndpoint,omitempty"`
	ApprovalURL                string   `json:"approvalURL,omitempty"`

	// File storage configuration
	StorageEnabled bool   `json:"storageEnabled,omitempty"`
	StoragePath    string `json:"storagePath,omitempty"`
	SaveInterval   int    `json:"saveInterval,omitempty"` // In seconds
	
	// Internal flag (not exposed to config)
	storageReadOnly bool   // Flag to indicate read-only storage mode
}

// StoredState represents the data that will be saved to disk
type StoredState struct {
	WhitelistedIPs   map[string]IPData `json:"whitelistedIPs"`
	PendingApprovals map[string]IPData `json:"pendingApprovals"`
	LastRequestedIP  map[string]string `json:"lastRequestedIP"` // Store as string for JSON compatibility
}

// IPData stores information about whitelisted IPs or pending approvals
type IPData struct {
	ExpiresAt       time.Time `json:"expiresAt"`      // Expiration time for whitelist entry OR pending request
	ValidationID    string    `json:"validationId"`   // Token associated with the request/entry
	ValidationCode  string    `json:"validationCode"` // User-facing code for verification
}

// CreateConfig creates a default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ExcludedIPs:                []string{},
		WhitelistedIPs:             []string{},
		IPStrategyDepth:            0,
		DefaultPrivateClassSources: true,
		ExpirationTime:             300, // Default 5 minutes whitelist duration
		SecretKey:                  generateRandomKey(),
		KnockEndpoint:              "/knock-knock",
		ApprovalURL:                "",

		// Default file storage configuration
		StorageEnabled: true,
		StoragePath:    "/plugins-storage/ipwhitelistshaper",
		SaveInterval:   30, // Default every 30 seconds
		storageReadOnly: false,
	}
}

// IPWhitelistShaper implements the middleware functionality
type IPWhitelistShaper struct {
	next               http.Handler
	name               string
	config             *Config
	whitelistedIPs     map[string]IPData // Map IP -> Whitelist Data
	pendingApprovals   map[string]IPData // Map IP -> Pending Approval Data
	lastRequestedIP    map[string]time.Time // Map IP -> Time of last knock request
	sourceRangeChecker *sourceRangeChecker
	mutex              sync.RWMutex // Protects maps: whitelistedIPs, pendingApprovals, lastRequestedIP
	wordList           []string
	ctx                context.Context
	cancel             context.CancelFunc // To stop background tasks
	stopChan           chan struct{}      // To signal periodic saver to stop
}

type sourceRangeChecker struct {
	ranges []net.IPNet
}

// New creates a new IPWhitelistShaper middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate config
	if config.StorageEnabled && config.StoragePath == "" {
		return nil, fmt.Errorf("storagePath must be set when storageEnabled is true")
	}
	if config.SaveInterval <= 0 && config.StorageEnabled {
		config.SaveInterval = 30 // Default if invalid
	}
	if config.ExpirationTime <= 0 {
		config.ExpirationTime = 300 // Default if invalid
	}

	// Initialize the source ranges
	sourceRanges := []string{"127.0.0.1/32"} // Always allow localhost
	if config.DefaultPrivateClassSources {
		sourceRanges = append(sourceRanges, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	}
	sourceRanges = append(sourceRanges, config.WhitelistedIPs...)

	checker, err := newSourceRangeChecker(sourceRanges)
	if err != nil {
		return nil, fmt.Errorf("error parsing source ranges: %v", err)
	}

	wordList := []string{
		"apple", "banana", "cherry", "dog", "elephant", "frog", "giraffe", "house",
		"igloo", "jacket", "kangaroo", "lemon", "monkey", "notebook", "orange", "penguin",
		"queen", "rainbow", "strawberry", "tiger", "umbrella", "violin", "watermelon",
		"xylophone", "yellow", "zebra", "airplane", "beach", "computer", "dolphin",
	}

	// Create context with cancellation for background tasks
	pluginCtx, cancel := context.WithCancel(ctx)

	middleware := &IPWhitelistShaper{
		next:               next,
		name:               name,
		config:             config,
		whitelistedIPs:     make(map[string]IPData),
		pendingApprovals:   make(map[string]IPData),
		lastRequestedIP:    make(map[string]time.Time),
		sourceRangeChecker: checker,
		wordList:           wordList,
		ctx:                pluginCtx, // Use the cancellable context
		cancel:             cancel,
		stopChan:           make(chan struct{}),
	}

	// Handle storage setup with graceful fallback
	if config.StorageEnabled {
		// Try to create the storage directory
		err := os.MkdirAll(config.StoragePath, 0755)
		if err != nil {
			// Check if directory exists but is just not writable
			if info, statErr := os.Stat(config.StoragePath); statErr == nil && info.IsDir() {
				// Directory exists but might be read-only
				fmt.Printf("[%s] WARNING: Storage directory exists but may not be writable: %v\n", name, err)
				config.storageReadOnly = true
			} else {
				// Try using a temporary directory instead
				tempDir := os.TempDir()
				tempStoragePath := filepath.Join(tempDir, "ipwhitelistshaper-"+name)
				fmt.Printf("[%s] WARNING: Cannot use configured storage path. Using temporary directory for storage: %s\n", 
					name, tempStoragePath)
				config.StoragePath = tempStoragePath
				
				// Try creating the temp directory
				if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
					fmt.Printf("[%s] WARNING: Cannot create storage directory: %v. Operating in memory-only mode.\n", name, err)
					// Operate in memory-only mode, but still try to load existing data
					config.storageReadOnly = true
				}
			}
		}

		// Try to load state regardless of write permissions
		if err = middleware.loadState(); err != nil && !os.IsNotExist(err) {
			fmt.Printf("[%s] WARNING: Could not load initial state from %s: %v\n", name, config.StoragePath, err)
		} else if err == nil {
			fmt.Printf("[%s] INFO Initial state loaded successfully from %s.\n", name, config.StoragePath)
		}

		// Only start background tasks if we have write permissions
		if !config.storageReadOnly {
			go middleware.periodicStateSaving()
			go middleware.cleanupExpiredEntries()
			fmt.Printf("[%s] INFO Started background tasks for state management.\n", name)
		} else {
			fmt.Printf("[%s] WARNING: Storage is in read-only mode. State will not be persisted.\n", name)
		}
	} else {
		fmt.Printf("[%s] INFO Storage is disabled. Operating in memory-only mode.\n", name)
	}

	return middleware, nil
}

// ServeHTTP implements the http.Handler interface for the middleware
func (i *IPWhitelistShaper) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := getClientIP(req, i.config.IPStrategyDepth, i.config.ExcludedIPs)
	if clientIP == "" {
		http.Error(rw, "Could not determine client IP", http.StatusInternalServerError)
		return
	}

	// Handle special endpoints first
	if req.URL.Path == i.config.KnockEndpoint {
		i.handleKnockRequest(rw, req, clientIP)
		return
	}
	if strings.HasPrefix(req.URL.Path, "/approve") {
		i.handleApproveRequest(rw, req)
		return
	}

	// --- Regular Request Flow ---
	if i.sourceRangeChecker.contains(clientIP) {
		i.next.ServeHTTP(rw, req)
		return
	}

	i.mutex.RLock()
	ipData, isWhitelisted := i.whitelistedIPs[clientIP]
	i.mutex.RUnlock()

	if isWhitelisted && time.Now().Before(ipData.ExpiresAt) {
		i.next.ServeHTTP(rw, req)
		return
	}

	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("403 Forbidden"))
}

// handleKnockRequest processes requests to the knock-knock endpoint
func (i *IPWhitelistShaper) handleKnockRequest(rw http.ResponseWriter, req *http.Request, clientIP string) {
	i.mutex.Lock()

	if ipData, isWhitelisted := i.whitelistedIPs[clientIP]; isWhitelisted && time.Now().Before(ipData.ExpiresAt) {
		i.mutex.Unlock()
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	if lastReq, exists := i.lastRequestedIP[clientIP]; exists && time.Since(lastReq) < 1*time.Minute {
		i.mutex.Unlock()
		rw.WriteHeader(http.StatusTooManyRequests)
		rw.Write([]byte("You have already requested approval recently. Please wait."))
		return
	}

	if pendingData, exists := i.pendingApprovals[clientIP]; exists && time.Now().Before(pendingData.ExpiresAt) {
		i.lastRequestedIP[clientIP] = time.Now()
		validationCode := pendingData.ValidationCode
		i.mutex.Unlock()
		if i.config.StorageEnabled && !i.config.storageReadOnly {
			if err := i.saveState(); err != nil { // Sync save lastRequestedIP update
				fmt.Printf("[%s] WARNING: Could not save state during knock re-request: %v\n", i.name, err)
			}
		}
		i.serveKnockPage(rw, validationCode, "An approval request is already pending. Please use the validation code below.")
		return
	}

	token := i.generateToken(clientIP)
	validationCode := i.getRandomWord()
	pendingExpiration := time.Now().Add(1 * time.Hour)

	i.pendingApprovals[clientIP] = IPData{
		ExpiresAt:      pendingExpiration,
		ValidationID:   token,
		ValidationCode: validationCode,
	}
	i.lastRequestedIP[clientIP] = time.Now()

	i.mutex.Unlock() // Unlock before synchronous save

	// Only try to save if storage is enabled and writable
	if i.config.StorageEnabled && !i.config.storageReadOnly {
		if err := i.saveState(); err != nil { // Synchronous save
			fmt.Printf("[%s] WARNING: Could not save state after creating pending approval: %v\n", i.name, err)
		} else {
			fmt.Printf("[%s] INFO State saved synchronously for pending approval IP: %s\n", i.name, clientIP)
		}
	}

	approvalURLBase := i.config.ApprovalURL
	if approvalURLBase == "" {
		approvalURLBase = fmt.Sprintf("%s://%s", getScheme(req), req.Host)
	}
	approvalLink := fmt.Sprintf("%s/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
		approvalURLBase, url.QueryEscape(clientIP), url.QueryEscape(token),
		url.QueryEscape(validationCode), i.config.ExpirationTime)

	message := fmt.Sprintf("Access request from %s\nValidation code: %s\nApprove: %s",
		clientIP, validationCode, approvalLink)
	i.sendNotification(message)

	i.serveKnockPage(rw, validationCode, "Your request requires approval. Please provide the validation code to the administrator.")
}

// serveKnockPage sends the HTML response for the knock endpoint
func (i *IPWhitelistShaper) serveKnockPage(rw http.ResponseWriter, validationCode, message string) {
	// (HTML content remains the same as previous version)
	html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Approval Required</title>
			<style>
				body { font-family: system-ui, sans-serif; background-color: #f0f4f8; color: #333; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
				.container { max-width: 500px; width: 100%%; background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); text-align: center; }
				h1 { color: #2c3e50; margin-bottom: 15px; }
				p { color: #555; margin-bottom: 25px; line-height: 1.6; }
				.highlight { background-color: #e0f2fe; padding: 8px 12px; border-radius: 4px; font-weight: bold; font-size: 1.2em; color: #0b72e0; display: inline-block; margin-top: 10px; border: 1px solid #b3d4fc; }
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Approval Required</h1>
				<p>%s</p>
				<p>Validation code: <span class="highlight">%s</span></p>
				<p>An administrator needs to approve your access using this code.</p>
			</div>
		</body>
		</html>
	`, message, validationCode)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(html))
}

// handleApproveRequest processes approval requests
func (i *IPWhitelistShaper) handleApproveRequest(rw http.ResponseWriter, req *http.Request) {
	ipEncoded := req.URL.Query().Get("ip")
	tokenEncoded := req.URL.Query().Get("token")
	validationCodeEncoded := req.URL.Query().Get("validationCode")
	expirationStr := req.URL.Query().Get("expiration")

	ip, err1 := url.QueryUnescape(ipEncoded)
	token, err2 := url.QueryUnescape(tokenEncoded)
	validationCode, err3 := url.QueryUnescape(validationCodeEncoded)

	if err1 != nil || err2 != nil || err3 != nil || ip == "" || token == "" {
		fmt.Printf("[%s] ERROR decoding approval parameters or missing params. IP: '%s', Token: '%s', Code: '%s', IP Err: %v, Token Err: %v, Code Err: %v\n", i.name, ip, token, validationCode, err1, err2, err3)
		http.Error(rw, "Invalid or missing request parameters", http.StatusBadRequest)
		return
	}

	// --- Start Critical Section ---
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Try to reload state, but don't fail if it doesn't work
	if i.config.StorageEnabled {
		// Try to reload, but ignore errors
		_ = i.loadStateFromFile()
		// Log debugging info
		fmt.Printf("[%s] DEBUG State loaded in handleApproveRequest for IP %s. Current pending map size: %d. Content samples: %+v\n", 
			i.name, ip, len(i.pendingApprovals), maskDebugData(i.pendingApprovals))
	}

	// Check if IP and token match the *now loaded* pending approval data
	pendingData, exists := i.pendingApprovals[ip]
	if !exists {
		// NEW CODE: Check if the IP is already whitelisted
		if whitelistData, isWhitelisted := i.whitelistedIPs[ip]; isWhitelisted {
			// IP is already approved, show success page but don't send notification again
			fmt.Printf("[%s] INFO IP %s is already whitelisted, expires at %s\n", 
				i.name, ip, whitelistData.ExpiresAt.Format(time.RFC3339))
			
			// Calculate remaining time
			remainingTime := int(time.Until(whitelistData.ExpiresAt).Seconds())
			if remainingTime < 0 {
				remainingTime = 0
			}
			
			// Show success page with already whitelisted message
			html := fmt.Sprintf(`
				<!DOCTYPE html>
				<html lang="en">
				<head>
					<meta charset="UTF-8">
					<meta name="viewport" content="width=device-width, initial-scale=1.0">
					<title>Already Approved</title>
					<style>
						body { font-family: system-ui, sans-serif; background-color: #f0f8f0; color: #333; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
						.container { max-width: 500px; width: 100%%; background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); text-align: center; }
						h1 { color: #2e7d32; margin-bottom: 15px; }
						p { color: #555; margin-bottom: 25px; line-height: 1.6; }
						.success { color: #2e7d32; font-weight: bold; font-size: 1.1em; }
						.ip-address { font-family: monospace; background-color: #e8f5e9; padding: 3px 6px; border-radius: 4px; }
						.expiration { font-style: italic; color: #777; margin-top: 15px; }
					</style>
				</head>
				<body>
					<div class="container">
						<h1>Already Approved</h1>
						<p><span class="success">IP address <span class="ip-address">%s</span> is already whitelisted.</span></p>
						<p class="expiration">Access will expire in %d seconds.</p>
					</div>
				</body>
				</html>
			`, ip, remainingTime)
			
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(html))
			return
		}
		
		// Original error message for IP not found in either list
		fmt.Printf("[%s] ERROR No pending approval found in current state for IP: %s (Token: %s). Approval attempt failed. Pending map keys: %v\n", 
			i.name, ip, token, getMapKeys(i.pendingApprovals))
		http.Error(rw, "Invalid token or IP address: No pending approval found", http.StatusForbidden)
		return
	}

	if pendingData.ValidationID != token {
		fmt.Printf("[%s] ERROR Token mismatch for IP: %s. Expected in state: '%s', Got from URL: '%s'\n", i.name, ip, pendingData.ValidationID, token)
		http.Error(rw, "Invalid token or IP address: Token mismatch", http.StatusForbidden)
		return
	}

	if pendingData.ValidationCode != validationCode {
		fmt.Printf("[%s] ERROR Validation code mismatch for IP: %s. Expected in state: '%s', Got from URL: '%s'\n", i.name, ip, pendingData.ValidationCode, validationCode)
		http.Error(rw, "Invalid validation code", http.StatusForbidden)
		return
	}
	// --- End Validation Section ---

	expirationTime := i.config.ExpirationTime
	if expirationStr != "" {
		_, err := fmt.Sscanf(expirationStr, "%d", &expirationTime)
		if err != nil || expirationTime <= 0 {
			expirationTime = i.config.ExpirationTime
		}
	}

	expiresAt := time.Now().Add(time.Duration(expirationTime) * time.Second)
	i.whitelistedIPs[ip] = IPData{
		ExpiresAt:      expiresAt,
		ValidationID:   token,
		ValidationCode: pendingData.ValidationCode,
	}
	delete(i.pendingApprovals, ip) // Remove from pending

	// Try to save state, but don't fail if it doesn't work
	if i.config.StorageEnabled && !i.config.storageReadOnly {
		if err := i.saveStateToFile(); err != nil {
			fmt.Printf("[%s] WARNING: Could not save state after approval: %v\n", i.name, err)
		} else {
			fmt.Printf("[%s] INFO State saved synchronously after approval for IP %s.\n", i.name, ip)
		}
	}
	// --- End Critical Section ---

	fmt.Printf("[%s] INFO Approved IP: %s, expiration: %d seconds\n", i.name, ip, expirationTime)
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ip, expirationTime)
	i.sendNotification(message)

	// Return success message
	html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Access Approved</title>
			<style>
				body { font-family: system-ui, sans-serif; background-color: #f0f8f0; color: #333; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
				.container { max-width: 500px; width: 100%%; background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); text-align: center; }
				h1 { color: #2e7d32; margin-bottom: 15px; }
				p { color: #555; margin-bottom: 25px; line-height: 1.6; }
				.success { color: #2e7d32; font-weight: bold; font-size: 1.1em; }
				.ip-address { font-family: monospace; background-color: #e8f5e9; padding: 3px 6px; border-radius: 4px; }
				.expiration { font-style: italic; color: #777; margin-top: 15px; }
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Access Approved</h1>
				<p><span class="success">IP address <span class="ip-address">%s</span> has been successfully whitelisted.</span></p>
				<p class="expiration">Access will expire in %d seconds.</p>
			</div>
		</body>
		</html>
	`, ip, expirationTime)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(html))
}
// Helper function for debug logging
func maskDebugData(data map[string]IPData) map[string]string {
	result := make(map[string]string)
	count := 0
	for k, v := range data {
		if count < 3 { // Only show up to 3 sample entries
			result[k] = fmt.Sprintf("ValidID: %s..., ValidCode: %s, Expires: %s", 
				truncateString(v.ValidationID, 8), 
				v.ValidationCode, 
				v.ExpiresAt.Format(time.RFC3339))
			count++
		}
	}
	return result
}

// Helper function to truncate strings for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// Helper function to get map keys for debugging
func getMapKeys(m map[string]IPData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// periodicStateSaving runs a background goroutine to periodically save state
func (i *IPWhitelistShaper) periodicStateSaving() {
	if !i.config.StorageEnabled || i.config.SaveInterval <= 0 || i.config.storageReadOnly {
		return
	}
	ticker := time.NewTicker(time.Duration(i.config.SaveInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.mutex.RLock()
			err := i.saveStateToFile()
			i.mutex.RUnlock()
			if err != nil {
				fmt.Printf("[%s] WARNING: Periodic state saving failed: %v\n", i.name, err)
			}
		case <-i.stopChan:
			return
		case <-i.ctx.Done():
			fmt.Printf("[%s] INFO Periodic state saving stopped due to context cancellation.\n", i.name)
			return
		}
	}
}

// cleanupExpiredEntries periodically removes expired entries from maps
func (i *IPWhitelistShaper) cleanupExpiredEntries() {
	if !i.config.StorageEnabled {
		return
	}
	cleanupInterval := 5 * time.Minute
	if i.config.SaveInterval > 0 && time.Duration(i.config.SaveInterval)*time.Second*10 > cleanupInterval {
		cleanupInterval = time.Duration(i.config.SaveInterval) * time.Second * 10
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			needsSave := false
			i.mutex.Lock()

			for ip, data := range i.whitelistedIPs {
				if now.After(data.ExpiresAt) {
					delete(i.whitelistedIPs, ip)
					needsSave = true
					fmt.Printf("[%s] INFO Cleaned up expired whitelist entry for IP: %s\n", i.name, ip)
				}
			}
			for ip, data := range i.pendingApprovals {
				if now.After(data.ExpiresAt) {
					delete(i.pendingApprovals, ip)
					needsSave = true
					fmt.Printf("[%s] INFO Cleaned up expired pending approval for IP: %s\n", i.name, ip)
				}
			}
			limit := now.Add(-1 * time.Hour)
			for ip, t := range i.lastRequestedIP {
				if t.Before(limit) {
					delete(i.lastRequestedIP, ip)
					needsSave = true
				}
			}
			i.mutex.Unlock()

			if needsSave && i.config.StorageEnabled && !i.config.storageReadOnly {
				go func() { // Save in background
					if err := i.saveState(); err != nil {
						fmt.Printf("[%s] WARNING: Could not save state after cleanup: %v\n", i.name, err)
					}
				}()
			}
		case <-i.stopChan:
			return
		case <-i.ctx.Done():
			fmt.Printf("[%s] INFO Expired entry cleanup stopped due to context cancellation.\n", i.name)
			return
		}
	}
}

// saveState acquires lock and calls saveStateToFile
func (i *IPWhitelistShaper) saveState() error {
	if !i.config.StorageEnabled || i.config.storageReadOnly {
		return nil
	}
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.saveStateToFile()
}

// saveStateToFile performs the actual saving logic, assumes RLock is held
func (i *IPWhitelistShaper) saveStateToFile() error {
	// Skip saving if storage is read-only
	if i.config.storageReadOnly {
		return nil
	}

	state := StoredState{
		WhitelistedIPs:   make(map[string]IPData),
		PendingApprovals: make(map[string]IPData),
		LastRequestedIP:  make(map[string]string),
	}
	now := time.Now()

	// Log debugging info about pending approvals
	fmt.Printf("[%s] DEBUG Saving state. Pending approvals to save: %d entries\n", i.name, len(i.pendingApprovals))

	for ip, data := range i.whitelistedIPs {
		if now.Before(data.ExpiresAt) {
			state.WhitelistedIPs[ip] = data
		}
	}
	for ip, data := range i.pendingApprovals {
		if now.Before(data.ExpiresAt) {
			state.PendingApprovals[ip] = data
		}
	}
	for ip, t := range i.lastRequestedIP {
		state.LastRequestedIP[ip] = t.Format(time.RFC3339)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %v", err)
	}

	tempFile := filepath.Join(i.config.StoragePath, fmt.Sprintf("state.json.tmp.%d", now.UnixNano()))
	err = ioutil.WriteFile(tempFile, data, 0644)
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to write temporary state file: %v", err)
	}

	stateFile := filepath.Join(i.config.StoragePath, "state.json")
	err = os.Rename(tempFile, stateFile)
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temporary state file to %s: %v", stateFile, err)
	}
	return nil
}

// loadState acquires lock and calls loadStateFromFile
func (i *IPWhitelistShaper) loadState() error {
	if !i.config.StorageEnabled {
		return nil
	}
	i.mutex.Lock()
	defer i.mutex.Unlock()
	
	err := i.loadStateFromFile()
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("[%s] WARNING: Could not load state: %v\n", i.name, err)
	}
	return nil
}

// loadStateFromFile performs the actual loading logic, assumes Lock is held
func (i *IPWhitelistShaper) loadStateFromFile() error {
	stateFile := filepath.Join(i.config.StoragePath, "state.json")
	data, err := ioutil.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			i.whitelistedIPs = make(map[string]IPData)
			i.pendingApprovals = make(map[string]IPData)
			i.lastRequestedIP = make(map[string]time.Time)
			fmt.Printf("[%s] INFO State file %s not found, initializing empty state.\n", i.name, stateFile)
			return nil
		}
		return fmt.Errorf("failed to read state file %s: %v", stateFile, err)
	}

	var state StoredState
	if err = json.Unmarshal(data, &state); err != nil {
		fmt.Printf("[%s] ERROR Failed to unmarshal state from %s: %v. Starting with empty state.\n", i.name, stateFile, err)
		i.whitelistedIPs = make(map[string]IPData)
		i.pendingApprovals = make(map[string]IPData)
		i.lastRequestedIP = make(map[string]time.Time)
		return nil
	}

	now := time.Now()
	tempWhitelistedIPs := make(map[string]IPData)
	tempPendingApprovals := make(map[string]IPData)
	tempLastRequestedIP := make(map[string]time.Time)

	if state.WhitelistedIPs != nil {
		for ip, data := range state.WhitelistedIPs {
			if now.Before(data.ExpiresAt) { tempWhitelistedIPs[ip] = data }
		}
	}
	if state.PendingApprovals != nil {
		for ip, data := range state.PendingApprovals {
			if now.Before(data.ExpiresAt) { tempPendingApprovals[ip] = data }
		}
	}
	if state.LastRequestedIP != nil {
		for ip, timeStr := range state.LastRequestedIP {
			if lastTime, err := time.Parse(time.RFC3339, timeStr); err == nil { tempLastRequestedIP[ip] = lastTime }
		}
	}

	i.whitelistedIPs = tempWhitelistedIPs
	i.pendingApprovals = tempPendingApprovals
	i.lastRequestedIP = tempLastRequestedIP

	// Log debug info after loading from file
	fmt.Printf("[%s] DEBUG State loaded from file %s. Pending approvals map size: %d.\n", 
		i.name, stateFile, len(i.pendingApprovals))
	return nil
}

// Close cleans up resources and ensures state is saved
func (i *IPWhitelistShaper) Close() error {
	fmt.Printf("[%s] INFO Shutting down IPWhitelistShaper middleware.\n", i.name)
	i.cancel()
	close(i.stopChan)
	if i.config.StorageEnabled && !i.config.storageReadOnly {
		i.mutex.RLock()
		err := i.saveStateToFile()
		i.mutex.RUnlock()
		if err != nil {
			fmt.Printf("[%s] WARNING: Could not save final state on close: %v\n", i.name, err)
		} else {
			fmt.Printf("[%s] INFO Final state saved successfully.\n", i.name)
		}
	}
	return nil
}

// --- Helper Functions --- (Remain the same as previous version with minor updates)
func (i *IPWhitelistShaper) generateToken(ip string) string {
	h := hmac.New(sha256.New, []byte(i.config.SecretKey))
	data := ip + fmt.Sprintf("%d", time.Now().UnixNano())
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil)[:16])
}
func (i *IPWhitelistShaper) getRandomWord() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if len(i.wordList) == 0 { return "approval" }
	return i.wordList[r.Intn(len(i.wordList))]
}
func (i *IPWhitelistShaper) sendNotification(message string) {
	if i.config.NotificationURL == "" { return }
	go func(msg string, urlStr string, ctx context.Context, pluginName string) {
		isDiscord := strings.Contains(strings.ToLower(urlStr), "discord.com/api/webhooks")
		var reqBody *bytes.Buffer
		contentType := "application/x-www-form-urlencoded"
		if isDiscord {
			payload := map[string]string{"content": msg}
			jsonData, err := json.Marshal(payload)
			if err != nil { fmt.Printf("[%s] ERROR creating Discord JSON payload: %v\n", pluginName, err); return }
			reqBody = bytes.NewBuffer(jsonData)
			contentType = "application/json"
		} else {
			values := url.Values{}; values.Set("message", msg)
			reqBody = bytes.NewBufferString(values.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, "POST", urlStr, reqBody)
		if err != nil { fmt.Printf("[%s] ERROR creating notification request: %v\n", pluginName, err); return }
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", "Traefik-IPWhitelistShaper-Plugin")
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil { fmt.Printf("[%s] ERROR sending notification to %s: %v\n", pluginName, urlStr, err) }
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			fmt.Printf("[%s] ERROR Notification webhook %s returned error (Status %d): %s\n", pluginName, urlStr, resp.StatusCode, string(bodyBytes))
		}
	}(message, i.config.NotificationURL, i.ctx, i.name)
}
func getClientIP(req *http.Request, depth int, excludedIPs []string) string {
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil { remoteIP = req.RemoteAddr }
	if depth > 0 {
		xff := req.Header.Get("X-Forwarded-For")
		if xff != "" {
			ips := strings.Split(xff, ",")
			processedIPs := make([]string, 0, len(ips))
			for _, ipStr := range ips {
				trimmedIP := strings.TrimSpace(ipStr)
				if net.ParseIP(trimmedIP) != nil { processedIPs = append(processedIPs, trimmedIP) }
			}
			if len(excludedIPs) > 0 {
				checker, err := newSourceRangeChecker(excludedIPs)
				if err == nil {
					filtered := make([]string, 0, len(processedIPs))
					for _, ip := range processedIPs { if !checker.contains(ip) { filtered = append(filtered, ip) } }
					if len(filtered) > 0 { processedIPs = filtered }
				} else { fmt.Printf("[ipwhitelistshaper] Warning: Could not parse excludedIPs for filtering: %v\n", err) }
			}
			if len(processedIPs) >= depth { targetIndex := len(processedIPs) - depth; return processedIPs[targetIndex] } else if len(processedIPs) > 0 { return processedIPs[0] }
		}
	}
	return remoteIP
}
func getScheme(req *http.Request) string {
	if req.TLS != nil { return "https" }
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" { return scheme }
	if scheme := req.Header.Get("X-Scheme"); scheme != "" { return scheme }
	return "http"
}
func newSourceRangeChecker(sourceRanges []string) (*sourceRangeChecker, error) {
	checker := &sourceRangeChecker{ ranges: make([]net.IPNet, 0, len(sourceRanges)) }
	for _, cidr := range sourceRanges {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" { continue }
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil { checker.ranges = append(checker.ranges, *ipNet); continue }
		ip := net.ParseIP(cidr)
		if ip != nil {
			var mask net.IPMask
			if ip.To4() != nil { mask = net.CIDRMask(32, 32) } else { mask = net.CIDRMask(128, 128) }
			checker.ranges = append(checker.ranges, net.IPNet{IP: ip, Mask: mask})
			continue
		}
		return nil, fmt.Errorf("invalid CIDR or IP address: %s", cidr)
	}
	return checker, nil
}
func (s *sourceRangeChecker) contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, ipNet := range s.ranges { if ipNet.Contains(ip) { return true } }
	return false
}
func generateRandomKey() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, 32)
	_, err := r.Read(bytes)
	if err != nil { for i := range bytes { bytes[i] = byte(r.Intn(256)) } }
	return hex.EncodeToString(bytes)
}