package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestMaxHeaderBytes_rejectsOversizedHeaders(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := newHTTPServer("", h)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			t.Errorf("serve: %v", err)
		}
	}()
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, "http://"+lis.Addr().String()+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Go's server allows one read buffer worth of data past MaxHeaderBytes,
	// so use a single header value comfortably above the 64 KB limit.
	req.Header.Set("X-Big", strings.Repeat("x", 100*1024))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status = %d, want %d (Request Header Fields Too Large)", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}
