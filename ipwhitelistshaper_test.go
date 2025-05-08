package ipwhitelistshaper_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hhftechnology/ipwhitelistshaper"
)

func TestIPWhitelistShaper(t *testing.T) {
	// Create a test configuration
	config := ipwhitelistshaper.CreateConfig()
	config.KnockEndpoint = "/knock-knock"
	config.WhitelistedIPs = []string{"192.168.1.1/32"}

	// Create a dummy next handler
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	// Create the middleware
	middleware, err := ipwhitelistshaper.New(context.Background(), next, config, "ipwhitelistshaper")
	if err != nil {
		t.Fatalf("Error creating middleware: %v", err)
	}

	// Test 1: Request from whitelisted IP should pass through
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	rec1 := httptest.NewRecorder()
	middleware.ServeHTTP(rec1, req1)

	// Check result
	if rec1.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rec1.Code)
	}
	if rec1.Body.String() != "OK" {
		t.Errorf("Expected body %q, got %q", "OK", rec1.Body.String())
	}

	// Test 2: Request from non-whitelisted IP should be forbidden
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	rec2 := httptest.NewRecorder()
	middleware.ServeHTTP(rec2, req2)

	// Check result (should be 403 Forbidden for non-whitelisted IPs)
	// Note: if DefaultPrivateClassSources is true (default), this will actually pass through
	// So we need to check based on the configuration
	if config.DefaultPrivateClassSources {
		if rec2.Code != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, rec2.Code)
		}
	} else {
		if rec2.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, rec2.Code)
		}
	}

	// Test 3: Request to knock-knock endpoint
	req3 := httptest.NewRequest(http.MethodGet, "http://localhost/knock-knock", nil)
	req3.RemoteAddr = "192.168.100.1:1234"
	rec3 := httptest.NewRecorder()
	middleware.ServeHTTP(rec3, req3)

	// Check result (should return 200 OK with HTML content)
	if rec3.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rec3.Code)
	}
	if rec3.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Expected Content-Type %q, got %q", "text/html", rec3.Header().Get("Content-Type"))
	}
}