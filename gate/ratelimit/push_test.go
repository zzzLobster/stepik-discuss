package ratelimit

import (
	"testing"
)

func TestAllowPush(t *testing.T) {
	s := NewStore()
	for range 20 {
		if ok, _ := s.AllowPush("sid-x"); !ok {
			t.Fatal("burst 20 denied early")
		}
	}
	if ok, _ := s.AllowPush("sid-x"); ok {
		t.Fatal("21st allowed")
	}
	if ok, _ := s.AllowPush("sid-y"); !ok {
		t.Fatal("fresh sid denied")
	}
}

func TestAllowPushByIP(t *testing.T) {
	s := NewStore()
	for range 30 {
		if ok, _ := s.AllowPushByIP("1.2.3.4"); !ok {
			t.Fatal("burst 30 denied early")
		}
	}
	if ok, retry := s.AllowPushByIP("1.2.3.4"); ok || retry < 1000000000 {
		t.Fatalf("31st allowed or no Retry-After: %v %v", ok, retry)
	}
}
