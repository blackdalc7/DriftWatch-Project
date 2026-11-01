package metrics

import (
	"context"
	"net"
	"testing"
)

func TestHostIPsSkipsLoopbackAndLinkLocal(t *testing.T) {
	ips := hostIPs()
	if len(ips) > 8 {
		t.Fatalf("at most eight addresses, got %d", len(ips))
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Fatalf("unexpected address %q", s)
		}
	}
}

func TestCollectReportsOnlyKnownKeys(t *testing.T) {
	known := map[string]bool{"cpu_percent": true, "memory_percent": true, "memory_total_bytes": true, "disk_percent": true,
		"disk_total_bytes": true, "uptime_seconds": true, "kernel_version": true, "ip_addresses": true, "load_average": true}
	for k := range Collect(context.Background()) {
		if !known[k] {
			t.Fatalf("server does not accept metric %q", k)
		}
	}
}
