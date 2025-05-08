package ipwhitelistshaper_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"reflect"
	"sync"

	"github.com/hhftechnology/ipwhitelistshaper" // Adjust import path if necessary
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a middleware instance for testing
func setupMiddleware(t *testing.T, config *ipwhitelistshaper.Config) (*ipwhitelistshaper.IPWhitelistShaper, http.HandlerFunc, string) {
	t.Helper() // Mark as test helper

	// Create a temporary directory for storage during the test
	tempDir, err := ioutil.TempDir("", "ipwhitelistshaper-test-")
	require.NoError(t, err, "Failed to create temp dir for testing")

	// Ensure config uses the temp dir if storage is enabled
	if config.StorageEnabled {
		config.StoragePath = tempDir
	} else {
		config.StoragePath = "" // Ensure path is empty if disabled
	}

	// Dummy next handler
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK - Service Reached"))
	})

	// Create middleware
	middlewareInstance, err := ipwhitelistshaper.New(context.Background(), next, config, "test-"+t.Name())
	require.NoError(t, err, "Error creating middleware")

	// Type assert to access internal state if needed (use cautiously)
	shaperInstance, ok := middlewareInstance.(*ipwhitelistshaper.IPWhitelistShaper)
	require.True(t, ok, "Middleware is not of expected type *IPWhitelistShaper")

	return shaperInstance, next, tempDir
}


func getPendingData(t *testing.T, shaper *ipwhitelistshaper.IPWhitelistShaper, ip string) (ipwhitelistshaper.IPData, bool) {
	t.Helper()
	
	shaperValue := reflect.ValueOf(shaper).Elem()
	configField := shaperValue.FieldByName("config")
	if !configField.IsValid() {
		t.Fatal("Could not find 'config' field in IPWhitelistShaper")
	}
	storageEnabled := configField.FieldByName("StorageEnabled").Bool()
	if storageEnabled {
		// Use reflection to call the unexported loadState method
		loadStateMethod := reflect.ValueOf(shaper).MethodByName("loadState")
		if !loadStateMethod.IsValid() {
			t.Fatal("Could not find 'loadState' method in IPWhitelistShaper")
		}
		results := loadStateMethod.Call(nil)
		if len(results) != 1 {
			t.Fatal("Unexpected number of return values from loadState")
		}
		if err, ok := results[0].Interface().(error); ok && err != nil {
			t.Fatalf("Failed to load state before getting pending data: %v", err)
		}
	}

	// Use reflection to access the unexported mutex field for locking
	shaperValue = reflect.ValueOf(shaper).Elem()
	mutexField := shaperValue.FieldByName("mutex")
	if !mutexField.IsValid() {
		t.Fatal("Could not find 'mutex' field in IPWhitelistShaper")
	}
	mutexPtr := mutexField.Addr().Interface().(*sync.RWMutex)
	mutexPtr.RLock()
	defer mutexPtr.RUnlock()

	// Use reflection to access the unexported pendingApprovals field for testing
	var data ipwhitelistshaper.IPData
	var exists bool
	field := shaperValue.FieldByName("pendingApprovals")
	if field.IsValid() {
		pendingMap := field.Interface().(map[string]ipwhitelistshaper.IPData)
		data, exists = pendingMap[ip]
	}
	return data, exists
}

func TestIPWhitelistShaper_CoreFlows(t *testing.T) {
	baseConfig := ipwhitelistshaper.CreateConfig()
	baseConfig.WhitelistedIPs = []string{"192.168.1.1/32"}
	baseConfig.StorageEnabled = true
	baseConfig.SaveInterval = 1 // Save quickly for tests
	baseConfig.ExpirationTime = 2 // Short expiration for testing
	baseConfig.ApprovalURL = "http://test.approve"
	baseConfig.NotificationURL = "" // Disable notifications

	shaper, _, tempDir := setupMiddleware(t, baseConfig)
	defer os.RemoveAll(tempDir) // Cleanup storage dir

	// --- Test Cases ---

	t.Run("Static Whitelisted IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK - Service Reached", rec.Body.String())
	})

	t.Run("Static Private IP (Default Allowed)", func(t *testing.T) {
		// Need a config where default is true
		config := ipwhitelistshaper.CreateConfig()
		config.DefaultPrivateClassSources = true
		config.StorageEnabled = false // No storage needed for this simple check
		shaperPrivate, _, _ := setupMiddleware(t, config)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		shaperPrivate.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Static Private IP (Default Denied)", func(t *testing.T) {
		config := ipwhitelistshaper.CreateConfig()
		config.DefaultPrivateClassSources = false // Explicitly disable
		config.StorageEnabled = false
		shaperNoPrivate, _, _ := setupMiddleware(t, config)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		shaperNoPrivate.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("Non-Whitelisted IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = "8.8.8.8:1234"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "IP not whitelisted")
	})
}

func TestIPWhitelistShaper_ApprovalFlow(t *testing.T) {
	baseConfig := ipwhitelistshaper.CreateConfig()
	baseConfig.StorageEnabled = true
	baseConfig.SaveInterval = 1
	baseConfig.ExpirationTime = 3 // 3 seconds expiration
	baseConfig.ApprovalURL = "http://test.approve"
	baseConfig.NotificationURL = "" // Disable notifications

	shaper, _, tempDir := setupMiddleware(t, baseConfig)
	defer os.RemoveAll(tempDir)

	knockIP := "172.18.0.10" // An IP not in static lists

	// 1. Initial request - should be forbidden
	t.Run("Initial Access Forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = knockIP + ":5000"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	// 2. Knock-Knock Request
	var validationCode string
	var token string
	t.Run("Knock Request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost"+baseConfig.KnockEndpoint, nil)
		req.RemoteAddr = knockIP + ":5001"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
		body := rec.Body.String()
		assert.Contains(t, body, "Validation code:")

		// Extract validation code for the next step (simple string parsing)
		codeStart := strings.Index(body, `<span class="highlight">`) + len(`<span class="highlight">`)
		codeEnd := strings.Index(body[codeStart:], `</span>`)
		require.True(t, codeStart > 0 && codeEnd > 0, "Could not find validation code in HTML")
		validationCode = body[codeStart : codeStart+codeEnd]
		assert.NotEmpty(t, validationCode, "Validation code should not be empty")

		// Allow time for state to be saved
		time.Sleep(150 * time.Millisecond) // Needs to be > SaveInterval potentially

		// Retrieve token from internal state (necessary for test without notification capture)
		pendingData, exists := getPendingData(t, shaper, knockIP)
		require.True(t, exists, "Pending approval data should exist after knock")
		token = pendingData.ValidationID
		assert.NotEmpty(t, token, "Token should not be empty")
		assert.Equal(t, validationCode, pendingData.ValidationCode, "Stored validation code should match the one shown")
	})

	// 3. Approval Request - Invalid Token
	t.Run("Approval Request Invalid Token", func(t *testing.T) {
		require.NotEmpty(t, validationCode, "Validation code needed for test")
		approveURL := fmt.Sprintf("/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
			url.QueryEscape(knockIP), "invalid-token", url.QueryEscape(validationCode), baseConfig.ExpirationTime)
		req := httptest.NewRequest(http.MethodGet, "http://localhost"+approveURL, nil)
		// Approval doesn't depend on RemoteAddr, but on params
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "Token mismatch")
	})

	// 4. Approval Request - Invalid Code
	t.Run("Approval Request Invalid Code", func(t *testing.T) {
		require.NotEmpty(t, token, "Token needed for test")
		approveURL := fmt.Sprintf("/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
			url.QueryEscape(knockIP), url.QueryEscape(token), "invalid-code", baseConfig.ExpirationTime)
		req := httptest.NewRequest(http.MethodGet, "http://localhost"+approveURL, nil)
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid validation code")
	})

	// 5. Approval Request - Valid
	t.Run("Approval Request Valid", func(t *testing.T) {
		require.NotEmpty(t, token, "Token needed for test")
		require.NotEmpty(t, validationCode, "Validation code needed for test")
		approveURL := fmt.Sprintf("/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
			url.QueryEscape(knockIP), url.QueryEscape(token), url.QueryEscape(validationCode), baseConfig.ExpirationTime)
		req := httptest.NewRequest(http.MethodGet, "http://localhost"+approveURL, nil)
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Access Approved")
		assert.Contains(t, rec.Body.String(), knockIP)

		// Verify pending approval is removed from state file
		time.Sleep(150 * time.Millisecond)
		stateFilePath := filepath.Join(tempDir, "state.json")
		content, readErr := ioutil.ReadFile(stateFilePath)
		require.NoError(t, readErr)
		var state ipwhitelistshaper.StoredState
		jsonErr := json.Unmarshal(content, &state)
		require.NoError(t, jsonErr)
		_, existsInPending := state.PendingApprovals[knockIP]
		assert.False(t, existsInPending, "IP should be removed from pending approvals in state file")
		_, existsInWhitelisted := state.WhitelistedIPs[knockIP]
		assert.True(t, existsInWhitelisted, "IP should be added to whitelisted IPs in state file")
	})

	// 6. Access After Approval (Before Expiration)
	t.Run("Access After Approval", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = knockIP + ":5002"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "OK - Service Reached", rec.Body.String())
	})

	// 7. Access After Expiration
	t.Run("Access After Expiration", func(t *testing.T) {
		// Wait for expiration (ExpirationTime + buffer)
		time.Sleep(time.Duration(baseConfig.ExpirationTime+1) * time.Second)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/protected", nil)
		req.RemoteAddr = knockIP + ":5003"
		rec := httptest.NewRecorder()
		shaper.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "Access should be forbidden after expiration")

		// Optional: Verify cleanup removed the entry (might need longer wait depending on cleanup interval)
		// err := shaper.LoadState() // Force reload
		// require.NoError(t, err)
		// shaper.Mutex().RLock()
		// _, exists := shaper.WhitelistedIPs()[knockIP]
		// shaper.Mutex().RUnlock()
		// assert.False(t, exists, "Expired IP should eventually be removed by cleanup")
	})
}

func TestIPWhitelistShaper_RateLimiting(t *testing.T) {
	baseConfig := ipwhitelistshaper.CreateConfig()
	baseConfig.StorageEnabled = true
	baseConfig.SaveInterval = 1
	baseConfig.NotificationURL = "" // Disable notifications

	shaper, _, tempDir := setupMiddleware(t, baseConfig)
	defer os.RemoveAll(tempDir)

	knockIP := "192.168.200.1"

	// First Knock Request
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost"+baseConfig.KnockEndpoint, nil)
	req1.RemoteAddr = knockIP + ":6000"
	rec1 := httptest.NewRecorder()
	shaper.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code, "First knock should be OK")

	// Immediate Second Knock Request
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost"+baseConfig.KnockEndpoint, nil)
	req2.RemoteAddr = knockIP + ":6001" // Same IP, different port
	rec2 := httptest.NewRecorder()
	shaper.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code, "Second immediate knock should be rate limited")

	// Wait a bit (less than the default 1 min limit in the code) and try again
	time.Sleep(10 * time.Second)
	req3 := httptest.NewRequest(http.MethodGet, "http://localhost"+baseConfig.KnockEndpoint, nil)
	req3.RemoteAddr = knockIP + ":6002"
	rec3 := httptest.NewRecorder()
	shaper.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusTooManyRequests, rec3.Code, "Third knock shortly after should still be rate limited")

	// Wait longer than the rate limit (assuming 1 minute from code)
	time.Sleep(61 * time.Second)
	req4 := httptest.NewRequest(http.MethodGet, "http://localhost"+baseConfig.KnockEndpoint, nil)
	req4.RemoteAddr = knockIP + ":6003"
	rec4 := httptest.NewRecorder()
	shaper.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusOK, rec4.Code, "Knock after rate limit period should be OK")
}