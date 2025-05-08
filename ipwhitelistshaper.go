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
	ExpirationTime             int      `json:"expirationTime,omitempty"`
	SecretKey                  string   `json:"secretKey,omitempty"`
	NotificationURL            string   `json:"notificationURL,omitempty"`
	KnockEndpoint              string   `json:"knockEndpoint,omitempty"`
	ApprovalURL                string   `json:"approvalURL,omitempty"`
	
	// File storage configuration
	StorageEnabled bool   `json:"storageEnabled,omitempty"`
	StoragePath    string `json:"storagePath,omitempty"`
	SaveInterval   int    `json:"saveInterval,omitempty"` // In seconds
}

// StoredState represents the data that will be saved to disk
type StoredState struct {
	WhitelistedIPs   map[string]IPData `json:"whitelistedIPs"`
	PendingApprovals map[string]IPData `json:"pendingApprovals"`
	LastRequestedIP  map[string]string `json:"lastRequestedIP"` // Store as string for JSON compatibility
}

// IPData stores information about whitelisted IPs
type IPData struct {
	ExpiresAt    time.Time `json:"expiresAt"`
	ValidationID string    `json:"validationId"`
	ValidationCode string    `json:"validationCode"` // New field
}

// CreateConfig creates a default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ExcludedIPs:                []string{},
		WhitelistedIPs:             []string{},
		IPStrategyDepth:            0,
		DefaultPrivateClassSources: true,
		ExpirationTime:             300,
		SecretKey:                  generateRandomKey(),
		KnockEndpoint:              "/knock-knock",
		ApprovalURL:                "",
		
		// Default file storage configuration
		StorageEnabled: true,
		StoragePath:    "/plugins-storage/ipwhitelistshaper",
		SaveInterval:   30, // Save every 30 seconds by default
	}
}

// IPWhitelistShaper implements the middleware functionality
type IPWhitelistShaper struct {
	next               http.Handler
	name               string
	config             *Config
	whitelistedIPs     map[string]IPData
	pendingApprovals   map[string]IPData
	lastRequestedIP    map[string]time.Time
	sourceRangeChecker *sourceRangeChecker
	mutex              sync.RWMutex
	wordList           []string
	ctx                context.Context
	stopChan           chan struct{} // Channel to stop background saving
}

type sourceRangeChecker struct {
	ranges []net.IPNet
}

// New creates a new IPWhitelistShaper middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Initialize the source ranges
	sourceRanges := []string{}

	// Always include localhost
	sourceRanges = append(sourceRanges, "127.0.0.1/32")

	// Add private class subnets if configured
	if config.DefaultPrivateClassSources {
		sourceRanges = append(sourceRanges, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	}

	// Add permanent whitelisted IPs
	sourceRanges = append(sourceRanges, config.WhitelistedIPs...)

	// Create and validate all IP ranges
	checker, err := newSourceRangeChecker(sourceRanges)
	if err != nil {
		return nil, fmt.Errorf("error creating source range checker: %v", err)
	}

	// Initialize the word list for validation codes
	wordList := []string{
		"apple", "banana", "cherry", "dog", "elephant", "frog", "giraffe", "house",
		"igloo", "jacket", "kangaroo", "lemon", "monkey", "notebook", "orange", "penguin",
		"queen", "rainbow", "strawberry", "tiger", "umbrella", "violin", "watermelon",
		"xylophone", "yellow", "zebra", "airplane", "beach", "computer", "dolphin",
	}

	// Initialize middleware
	middleware := &IPWhitelistShaper{
		next:               next,
		name:               name,
		config:             config,
		whitelistedIPs:     make(map[string]IPData),
		pendingApprovals:   make(map[string]IPData),
		lastRequestedIP:    make(map[string]time.Time),
		sourceRangeChecker: checker,
		wordList:           wordList,
		ctx:                ctx,
		stopChan:           make(chan struct{}),
	}
	
	// Initialize storage directory if enabled
	if config.StorageEnabled {
		err := os.MkdirAll(config.StoragePath, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage directory: %v", err)
		}
		
		// Load initial state from file
		err = middleware.loadState()
		if err != nil {
			// Log error but continue - this might be the first run
			fmt.Printf("Warning: Could not load initial state: %v\n", err)
		}
		
		// Start background saving
		go middleware.periodicStateSaving()
	}
	
	return middleware, nil
}

// ServeHTTP implements the http.Handler interface for the middleware
func (i *IPWhitelistShaper) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Get client IP based on the configured strategy
	clientIP := getClientIP(req, i.config.IPStrategyDepth, i.config.ExcludedIPs)

	// Handle knock-knock endpoint
	if req.URL.Path == i.config.KnockEndpoint {
		i.handleKnockRequest(rw, req, clientIP)
		return
	}

	// Handle approval endpoint
	if strings.HasPrefix(req.URL.Path, "/approve") {
		i.handleApproveRequest(rw, req)
		return
	}

	// Check if IP is statically whitelisted through the source range checker
	if i.sourceRangeChecker.contains(clientIP) {
		i.next.ServeHTTP(rw, req)
		return
	}

	// Check if IP is dynamically whitelisted
	i.mutex.RLock()
	ipData, isWhitelisted := i.whitelistedIPs[clientIP]
	i.mutex.RUnlock()

	// Check if IP is in dynamic whitelist and not expired
	if isWhitelisted {
		if time.Now().Before(ipData.ExpiresAt) {
			i.next.ServeHTTP(rw, req)
			return
		} else {
			// IP whitelist has expired, remove it
			i.mutex.Lock()
			delete(i.whitelistedIPs, clientIP)
			i.mutex.Unlock()

			// Save state after modifying it
			if i.config.StorageEnabled {
				go i.saveState()
			}

			// Send notification about expiration
			msg := fmt.Sprintf("❌ Removed %s from whitelist. Access revoked.", clientIP)
			i.sendNotification(msg)
		}
	}

	// IP is not whitelisted, return 403 Forbidden
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("IP not whitelisted. Visit " + i.config.KnockEndpoint + " to request access."))
}

// handleKnockRequest processes requests to the knock-knock endpoint
func (i *IPWhitelistShaper) handleKnockRequest(rw http.ResponseWriter, req *http.Request, clientIP string) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Check if the IP is already whitelisted
	if ipData, isWhitelisted := i.whitelistedIPs[clientIP]; isWhitelisted && time.Now().Before(ipData.ExpiresAt) {
		// Redirect to root
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	// Check if there's a pending approval for this IP within the last 5 minutes
	if lastReq, exists := i.lastRequestedIP[clientIP]; exists {
		if time.Since(lastReq) < 5*time.Minute {
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte("You have already requested approval within the last 5 minutes."))
			return
		}
	}

	// Update the last request time
	i.lastRequestedIP[clientIP] = time.Now()

	// Generate token and validation code
	token := i.generateToken(clientIP)
	validationCode := i.getRandomWord()

	// Set expiration time
	expiration := time.Now().Add(time.Duration(i.config.ExpirationTime) * time.Second)
    fmt.Printf("DEBUG: Storing token %s for IP %s\n", token, clientIP) // Add debugging
	// Store pending approval
	i.pendingApprovals[clientIP] = IPData{
		ExpiresAt:    expiration,
		ValidationID: token,
	}
    fmt.Printf("DEBUG: Current pending approvals: %+v\n", i.pendingApprovals)
	// Save state after modifying it
	if i.config.StorageEnabled {
		go i.saveState()
	}

	// Construct approval link
	approvalURL := i.config.ApprovalURL
	if approvalURL == "" {
		// Default to the same host if not configured
		approvalURL = fmt.Sprintf("%s://%s", getScheme(req), req.Host)
	}
	approvalLink := fmt.Sprintf("%s/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
		approvalURL, url.QueryEscape(clientIP), url.QueryEscape(token),
		url.QueryEscape(validationCode), i.config.ExpirationTime)

	// Send notification with approval link
	message := fmt.Sprintf("Access request from %s\nValidation code: %s\nApprove: %s",
		clientIP, validationCode, approvalLink)
	i.sendNotification(message)

	// Return response to user
	html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Approval Required</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #f4f4f4;
					padding: 20px;
				}
				.container {
					max-width: 600px;
					margin: auto;
					background-color: #fff;
					border-radius: 5px;
					padding: 20px;
					box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
				}
				h1 {
					color: #333;
				}
				p {
					color: #555;
					margin-bottom: 20px;
				}
				.highlight {
					background-color: #ffffcc;
					padding: 5px;
					font-weight: bold;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Approval Required</h1>
				<p>Your request requires approval. Please wait while we process your request.</p>
				<p>Validation code: <span class="highlight">%s</span></p>
				<p>An administrator will review your request shortly.</p>
			</div>
		</body>
		</html>
	`, validationCode)

	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(html))
}

// handleApproveRequest processes approval requests
func (i *IPWhitelistShaper) handleApproveRequest(rw http.ResponseWriter, req *http.Request) {
	rawIP := req.URL.Query().Get("ip")
	rawToken := req.URL.Query().Get("token")
	fmt.Printf("DEBUG: Received approval request for IP: %s, Token: %s\n", rawIP, rawToken)
    // Get encoded parameters from URL
    ipEncoded := req.URL.Query().Get("ip")
    tokenEncoded := req.URL.Query().Get("token")
    validationCodeEncoded := req.URL.Query().Get("validationCode") 
    expirationStr := req.URL.Query().Get("expiration")

    // Decode URL parameters
    ip, err1 := url.QueryUnescape(ipEncoded)
    token, err2 := url.QueryUnescape(tokenEncoded)
    validationCode, err3 := url.QueryUnescape(validationCodeEncoded)

    // Handle decoding errors (optional but recommended)
    if err1 != nil || err2 != nil || err3 != nil {
        rw.WriteHeader(http.StatusBadRequest)
        rw.Write([]byte("Error decoding URL parameters"))
        return
    }

    // Validate parameters
    if ip == "" || token == "" {
        rw.WriteHeader(http.StatusBadRequest)
        rw.Write([]byte("Invalid request parameters"))
        return
    }

    // For validationCode - either use it for validation or use the blank identifier
    // Option 1: Use it for validation
    // The rest of your function using the decoded variables...
    
    // Lock for modifications
    i.mutex.Lock()
    defer i.mutex.Unlock()

    // Check if IP and token match
    pendingData, exists := i.pendingApprovals[ip]
    if !exists || pendingData.ValidationID != token {
        rw.WriteHeader(http.StatusForbidden)
        rw.Write([]byte("Invalid token or IP address"))
        return
    }

    // Optional: Validate the validation code if needed
    // If ValidationCode is stored in your IPData struct
    if pendingData.ValidationCode != validationCode {
        rw.WriteHeader(http.StatusForbidden)
        rw.Write([]byte("Invalid validation code"))
        return
    }

	// Parse expiration time
	expirationTime := i.config.ExpirationTime
	if expirationStr != "" {
		_, err := fmt.Sscanf(expirationStr, "%d", &expirationTime)
		if err != nil {
			expirationTime = i.config.ExpirationTime
		}
	}

	// Add IP to whitelist
	i.whitelistedIPs[ip] = IPData{
		ExpiresAt:    time.Now().Add(time.Duration(expirationTime) * time.Second),
		ValidationID: token,
	}

	// Remove from pending approvals
	delete(i.pendingApprovals, ip)

	// Save state after modifying it
	if i.config.StorageEnabled {
		go i.saveState()
	}

	// Send notification
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ip, expirationTime)
	i.sendNotification(message)

	// Return success message with HTML formatting
	html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Access Approved</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #f4f4f4;
					padding: 20px;
				}
				.container {
					max-width: 600px;
					margin: auto;
					background-color: #fff;
					border-radius: 5px;
					padding: 20px;
					box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
				}
				h1 {
					color: #333;
				}
				p {
					color: #555;
					margin-bottom: 20px;
				}
				.success {
					color: #4CAF50;
					font-weight: bold;
				}
				.expiration {
					font-style: italic;
					color: #777;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>Access Approved</h1>
				<p><span class="success">IP address %s has been approved and added to the whitelist.</span></p>
				<p class="expiration">Access will expire in %d seconds.</p>
			</div>
		</body>
		</html>
	`, ip, expirationTime)

	rw.Header().Set("Content-Type", "text/html")
	rw.Write([]byte(html))
}

// periodicStateSaving runs a background goroutine to periodically save state
func (i *IPWhitelistShaper) periodicStateSaving() {
	ticker := time.NewTicker(time.Duration(i.config.SaveInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.saveState()
		case <-i.stopChan:
			return
		}
	}
}

// saveState saves the current state to disk
func (i *IPWhitelistShaper) saveState() error {
	if !i.config.StorageEnabled {
		return nil
	}

	i.mutex.RLock()
	defer i.mutex.RUnlock()
	
	// Create a copy of the current state
	state := StoredState{
		WhitelistedIPs:   make(map[string]IPData),
		PendingApprovals: make(map[string]IPData),
		LastRequestedIP:  make(map[string]string),
	}
	
	// Copy whitelisted IPs
	for ip, data := range i.whitelistedIPs {
		// Skip expired entries
		if time.Now().After(data.ExpiresAt) {
			continue
		}
		state.WhitelistedIPs[ip] = data
	}
	
	// Copy pending approvals
	for ip, data := range i.pendingApprovals {
		// Skip expired entries
		if time.Now().After(data.ExpiresAt) {
			continue
		}
		state.PendingApprovals[ip] = data
	}
	
	// Copy last requested times
	for ip, lastTime := range i.lastRequestedIP {
		state.LastRequestedIP[ip] = lastTime.Format(time.RFC3339)
	}
	
	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %v", err)
	}
	
	// Write to a temporary file first
	tempFile := filepath.Join(i.config.StoragePath, "state.json.tmp")
	err = ioutil.WriteFile(tempFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write temporary state file: %v", err)
	}
	
	// Atomically replace the old file
	stateFile := filepath.Join(i.config.StoragePath, "state.json")
	err = os.Rename(tempFile, stateFile)
	if err != nil {
		return fmt.Errorf("failed to rename temporary state file: %v", err)
	}
	
	return nil
}

// loadState loads the state from disk
func (i *IPWhitelistShaper) loadState() error {
	if !i.config.StorageEnabled {
		return nil
	}
	
	stateFile := filepath.Join(i.config.StoragePath, "state.json")
	
	// Check if file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return nil // Not an error, just no state yet
	}
	
	// Read file
	data, err := ioutil.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read state file: %v", err)
	}
	
	// Unmarshal from JSON
	var state StoredState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return fmt.Errorf("failed to unmarshal state: %v", err)
	}
	
	i.mutex.Lock()
	defer i.mutex.Unlock()
	
	// Restore whitelisted IPs
	for ip, data := range state.WhitelistedIPs {
		// Skip expired entries
		if time.Now().After(data.ExpiresAt) {
			continue
		}
		i.whitelistedIPs[ip] = data
	}
	
	// Restore pending approvals
	for ip, data := range state.PendingApprovals {
		// Skip expired entries
		if time.Now().After(data.ExpiresAt) {
			continue
		}
		i.pendingApprovals[ip] = data
	}
	
	// Restore last requested times
	for ip, timeStr := range state.LastRequestedIP {
		lastTime, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			continue // Skip this entry if we can't parse the time
		}
		i.lastRequestedIP[ip] = lastTime
	}
	
	return nil
}

// Close cleans up resources and ensures state is saved
func (i *IPWhitelistShaper) Close() error {
	// Signal the background saving goroutine to stop
	close(i.stopChan)
	
	// Save state one last time
	if i.config.StorageEnabled {
		return i.saveState()
	}
	
	return nil
}

// generateToken creates a secure token for an IP
func (i *IPWhitelistShaper) generateToken(ip string) string {
	h := hmac.New(sha256.New, []byte(i.config.SecretKey))
	data := ip + fmt.Sprintf("%d", time.Now().Unix())
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// getRandomWord returns a random word for validation
func (i *IPWhitelistShaper) getRandomWord() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return i.wordList[r.Intn(len(i.wordList))]
}

// sendNotification sends a notification message to the configured URL
func (i *IPWhitelistShaper) sendNotification(message string) {
	// Skip if no notification URL is configured
	if i.config.NotificationURL == "" {
		return
	}

	// Check if it's a Discord webhook
	isDiscord := strings.Contains(strings.ToLower(i.config.NotificationURL), "discord.com/api/webhooks")

	// Make an HTTP POST request to the notification URL
	go func() {
		var req *http.Request
		var err error

		if isDiscord {
			// For Discord webhooks, we need to send JSON
			payload := map[string]string{
				"content": message,
			}
			
			jsonData, err := json.Marshal(payload)
			if err != nil {
				fmt.Printf("Error creating JSON payload: %v\n", err)
				return
			}
			
			// Create a POST request with JSON content type
			req, err = http.NewRequest("POST", i.config.NotificationURL, bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Printf("Error creating request: %v\n", err)
				return
			}
			
			req.Header.Set("Content-Type", "application/json")
		} else {
			// For other webhooks, use form data
			values := url.Values{}
			values.Set("message", message)
			
			req, err = http.NewRequest("POST", i.config.NotificationURL, 
				strings.NewReader(values.Encode()))
			if err != nil {
				fmt.Printf("Error creating request: %v\n", err)
				return
			}
			
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		
		// Add a timeout to the client
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error sending notification: %v\n", err)
			return
		}
		defer resp.Body.Close()
		
		// Check for error responses
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Printf("Notification webhook error (Status %d): %s\n", resp.StatusCode, string(body))
		}
	}()
}

// getClientIP extracts the client IP based on the chosen strategy
func getClientIP(req *http.Request, depth int, excludedIPs []string) string {
	// First try X-Forwarded-For header
	if depth > 0 {
		forwardedFor := req.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			ips := strings.Split(forwardedFor, ",")
			// Trim spaces
			for i := range ips {
				ips[i] = strings.TrimSpace(ips[i])
			}

			// Apply exclusion if configured
			if len(excludedIPs) > 0 {
				filtered := filterExcludedIPs(ips, excludedIPs)
				if len(filtered) > 0 {
					ips = filtered
				}
			}

			// Apply depth
			if len(ips) > depth {
				return ips[len(ips)-depth-1]
			} else if len(ips) > 0 {
				return ips[0]
			}
		}
	}

	// Default to RemoteAddr
	remoteAddr := req.RemoteAddr
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // return as is if no port
	}
	return ip
}

// filterExcludedIPs removes excluded IPs from the list
func filterExcludedIPs(ips []string, excludedIPs []string) []string {
	excludeMap := make(map[string]bool)
	for _, ip := range excludedIPs {
		excludeMap[ip] = true
	}

	var result []string
	for _, ip := range ips {
		if !excludeMap[ip] {
			result = append(result, ip)
		}
	}
	return result
}

// getScheme determines the scheme (http/https) from the request
func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if req.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// newSourceRangeChecker creates a new checker for IP source ranges
func newSourceRangeChecker(sourceRanges []string) (*sourceRangeChecker, error) {
	checker := &sourceRangeChecker{
		ranges: []net.IPNet{},
	}

	for _, cidr := range sourceRanges {
		if cidr != "" {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				// Try treating it as an IP without mask
				ip := net.ParseIP(cidr)
				if ip == nil {
					return nil, fmt.Errorf("invalid CIDR notation or IP: %s", cidr)
				}

				// Determine mask based on IP type
				var mask net.IPMask
				if ip.To4() != nil {
					// IPv4 address
					mask = net.CIDRMask(32, 32)
				} else {
					// IPv6 address
					mask = net.CIDRMask(128, 128)
				}

				ipNet = &net.IPNet{
					IP:   ip,
					Mask: mask,
				}
			}
			checker.ranges = append(checker.ranges, *ipNet)
		}
	}

	return checker, nil
}

// contains checks if an IP is in any of the configured ranges
func (s *sourceRangeChecker) contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipNet := range s.ranges {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// generateRandomKey creates a random key for HMAC
func generateRandomKey() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, 16)
	for i := range bytes {
		bytes[i] = byte(r.Intn(256))
	}
	return hex.EncodeToString(bytes)
}