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
	"strings"
	"sync"
	"time"


	"github.com/go-redis/redis/v8"
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
	
	// Redis configuration
	RedisEnabled   bool   `json:"redisEnabled,omitempty"`
	RedisAddress   string `json:"redisAddress,omitempty"`
	RedisPassword  string `json:"redisPassword,omitempty"`
	RedisDB        int    `json:"redisDB,omitempty"`
	RedisKeyPrefix string `json:"redisKeyPrefix,omitempty"`
}

// IPData stores information about whitelisted IPs
type IPData struct {
	ExpiresAt    time.Time `json:"expiresAt"`
	ValidationID string    `json:"validationId"`
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
		
		// Default Redis configuration
		RedisEnabled:   false,
		RedisAddress:   "localhost:6379",
		RedisPassword:  "",
		RedisDB:        0,
		RedisKeyPrefix: "ipwhitelistshaper:",
	}
}

// IPWhitelistShaper implements the middleware functionality
type IPWhitelistShaper struct {
	next               http.Handler
	name               string
	config             *Config
	whitelistedIPs     map[string]IPData  // Fallback for when Redis is disabled
	pendingApprovals   map[string]IPData  // Fallback for when Redis is disabled
	lastRequestedIP    map[string]time.Time
	sourceRangeChecker *sourceRangeChecker
	mutex              sync.RWMutex
	wordList           []string
	redisClient        *redis.Client
	ctx                context.Context
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

	// Initialize middleware with or without Redis
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
	}
	
	// Initialize Redis client if enabled
	if config.RedisEnabled {
		middleware.redisClient = redis.NewClient(&redis.Options{
			Addr:     config.RedisAddress,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})
		
		// Ping Redis to verify connection
		_, err := middleware.redisClient.Ping(ctx).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Redis: %v", err)
		}
		
		fmt.Printf("Successfully connected to Redis at %s\n", config.RedisAddress)
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
	isWhitelisted := i.isIPWhitelisted(clientIP)
	if isWhitelisted {
		i.next.ServeHTTP(rw, req)
		return
	}

	// Clean up expired whitelisted IPs
	i.cleanupExpiredWhitelists(clientIP)

	// IP is not whitelisted, return 403 Forbidden
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("IP not whitelisted. Visit " + i.config.KnockEndpoint + " to request access."))
}

// isIPWhitelisted checks if an IP is in the whitelist
func (i *IPWhitelistShaper) isIPWhitelisted(clientIP string) bool {
	if !i.config.RedisEnabled {
		i.mutex.RLock()
		ipData, isWhitelisted := i.whitelistedIPs[clientIP]
		i.mutex.RUnlock()
		return isWhitelisted && time.Now().Before(ipData.ExpiresAt)
	}
	
	// Check in Redis
	key := i.config.RedisKeyPrefix + "whitelist:" + clientIP
	val, err := i.redisClient.Get(i.ctx, key).Result()
	if err != nil {
		// Key doesn't exist or Redis error
		return false
	}
	
	// Parse stored data
	var ipData IPData
	err = json.Unmarshal([]byte(val), &ipData)
	if err != nil {
		fmt.Printf("Error unmarshaling Redis data for IP %s: %v\n", clientIP, err)
		return false
	}
	
	// Check if the whitelist entry has expired
	if time.Now().After(ipData.ExpiresAt) {
		// Clean up the expired entry
		i.redisClient.Del(i.ctx, key)
		return false
	}
	
	return true
}

// cleanupExpiredWhitelists removes expired dynamic whitelists
func (i *IPWhitelistShaper) cleanupExpiredWhitelists(clientIP string) {
	if !i.config.RedisEnabled {
		// For in-memory maps, check and remove expired entries
		i.mutex.Lock()
		defer i.mutex.Unlock()
		
		if ipData, exists := i.whitelistedIPs[clientIP]; exists && time.Now().After(ipData.ExpiresAt) {
			delete(i.whitelistedIPs, clientIP)
			
			// Send notification about expiration if configured
			msg := fmt.Sprintf("❌ Removed %s from whitelist. Access revoked.", clientIP)
			i.sendNotification(msg)
		}
		return
	}
	
	// Redis TTL handles expiration automatically, but we can trigger a manual
	// cleanup when we see an expired entry to ensure consistency
	key := i.config.RedisKeyPrefix + "whitelist:" + clientIP
	ttl, err := i.redisClient.TTL(i.ctx, key).Result()
	if err == nil && ttl <= 0 {
		i.redisClient.Del(i.ctx, key)
		
		// Send notification about expiration if configured
		msg := fmt.Sprintf("❌ Removed %s from whitelist. Access revoked.", clientIP)
		i.sendNotification(msg)
	}
}

// handleKnockRequest processes requests to the knock-knock endpoint
func (i *IPWhitelistShaper) handleKnockRequest(rw http.ResponseWriter, req *http.Request, clientIP string) {
	// Check if the IP is already whitelisted
	isWhitelisted := i.isIPWhitelisted(clientIP)
	if isWhitelisted {
		// Redirect to root
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	// Check if there's a pending approval for this IP within the last 5 minutes
	lastRequested, err := i.getLastRequestTime(clientIP)
	if err == nil && time.Since(lastRequested) < 5*time.Minute {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("You have already requested approval within the last 5 minutes."))
		return
	}

	// Update the last request time
	i.setLastRequestTime(clientIP)

	// Generate token and validation code
	token := i.generateToken(clientIP)
	validationCode := i.getRandomWord()

	// Set expiration time
	expiration := time.Now().Add(time.Duration(i.config.ExpirationTime) * time.Second)

	// Store pending approval
	i.storePendingApproval(clientIP, token, expiration)

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

// getLastRequestTime retrieves the time of the last request for this IP
func (i *IPWhitelistShaper) getLastRequestTime(clientIP string) (time.Time, error) {
	if !i.config.RedisEnabled {
		i.mutex.RLock()
		lastReq, exists := i.lastRequestedIP[clientIP]
		i.mutex.RUnlock()
		if !exists {
			return time.Time{}, fmt.Errorf("no last request time")
		}
		return lastReq, nil
	}
	
	key := i.config.RedisKeyPrefix + "lastreq:" + clientIP
	val, err := i.redisClient.Get(i.ctx, key).Result()
	if err != nil {
		return time.Time{}, err
	}
	
	lastReq, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, err
	}
	
	return lastReq, nil
}

// setLastRequestTime updates the last request time for this IP
func (i *IPWhitelistShaper) setLastRequestTime(clientIP string) {
	now := time.Now()
	
	if !i.config.RedisEnabled {
		i.mutex.Lock()
		i.lastRequestedIP[clientIP] = now
		i.mutex.Unlock()
		return
	}
	
	key := i.config.RedisKeyPrefix + "lastreq:" + clientIP
	i.redisClient.Set(i.ctx, key, now.Format(time.RFC3339), 24*time.Hour)
}

// storePendingApproval stores a pending approval request
func (i *IPWhitelistShaper) storePendingApproval(clientIP, token string, expiration time.Time) {
	ipData := IPData{
		ExpiresAt:    expiration,
		ValidationID: token,
	}
	
	if !i.config.RedisEnabled {
		i.mutex.Lock()
		i.pendingApprovals[clientIP] = ipData
		i.mutex.Unlock()
		return
	}
	
	// Store in Redis
	key := i.config.RedisKeyPrefix + "pending:" + clientIP
	jsonData, _ := json.Marshal(ipData)
	i.redisClient.Set(i.ctx, key, jsonData, time.Until(expiration))
}

// handleApproveRequest processes approval requests
func (i *IPWhitelistShaper) handleApproveRequest(rw http.ResponseWriter, req *http.Request) {
	// Parse query parameters
	ip := req.URL.Query().Get("ip")
	token := req.URL.Query().Get("token")
	expirationStr := req.URL.Query().Get("expiration")

	// Validate parameters
	if ip == "" || token == "" {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Invalid request parameters"))
		return
	}

	// Check if IP and token match
	pendingData, exists := i.getPendingApproval(ip)
	if !exists || pendingData.ValidationID != token {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("Invalid token or IP address"))
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
	expiration := time.Now().Add(time.Duration(expirationTime) * time.Second)
	i.addToWhitelist(ip, token, expiration)
	
	// Remove from pending approvals
	i.removePendingApproval(ip)

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

// getPendingApproval retrieves a pending approval request
func (i *IPWhitelistShaper) getPendingApproval(ip string) (IPData, bool) {
	if !i.config.RedisEnabled {
		i.mutex.RLock()
		data, exists := i.pendingApprovals[ip]
		i.mutex.RUnlock()
		return data, exists
	}
	
	key := i.config.RedisKeyPrefix + "pending:" + ip
	val, err := i.redisClient.Get(i.ctx, key).Result()
	if err != nil {
		return IPData{}, false
	}
	
	var ipData IPData
	err = json.Unmarshal([]byte(val), &ipData)
	if err != nil {
		fmt.Printf("Error unmarshaling pending approval data: %v\n", err)
		return IPData{}, false
	}
	
	return ipData, true
}

// addToWhitelist adds an IP to the whitelist
func (i *IPWhitelistShaper) addToWhitelist(ip, token string, expiration time.Time) {
	ipData := IPData{
		ExpiresAt:    expiration,
		ValidationID: token,
	}
	
	if !i.config.RedisEnabled {
		i.mutex.Lock()
		i.whitelistedIPs[ip] = ipData
		i.mutex.Unlock()
		return
	}
	
	key := i.config.RedisKeyPrefix + "whitelist:" + ip
	jsonData, _ := json.Marshal(ipData)
	i.redisClient.Set(i.ctx, key, jsonData, time.Until(expiration))
}

// removePendingApproval removes a pending approval request
func (i *IPWhitelistShaper) removePendingApproval(ip string) {
	if !i.config.RedisEnabled {
		i.mutex.Lock()
		delete(i.pendingApprovals, ip)
		i.mutex.Unlock()
		return
	}
	
	key := i.config.RedisKeyPrefix + "pending:" + ip
	i.redisClient.Del(i.ctx, key)
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

// Close cleans up resources when the middleware is being shut down
func (i *IPWhitelistShaper) Close() error {
	if i.config.RedisEnabled && i.redisClient != nil {
		return i.redisClient.Close()
	}
	return nil
}