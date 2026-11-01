// Package metrics gathers the heartbeat host metrics with gopsutil.
package metrics

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func rootPath() string {
	if runtime.GOOS == "windows" {
		return filepath.VolumeName(`C:\`) + `\`
	}
	return "/"
}

// Collect returns the metrics the server accepts. Missing values are left out rather than faked.
func Collect(ctx context.Context) map[string]any {
	out := map[string]any{}
	if pct, err := cpu.PercentWithContext(ctx, time.Second, false); err == nil && len(pct) > 0 {
		out["cpu_percent"] = round1(pct[0])
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out["memory_percent"] = round1(vm.UsedPercent)
		out["memory_total_bytes"] = vm.Total
	}
	if du, err := disk.UsageWithContext(ctx, rootPath()); err == nil {
		out["disk_percent"] = round1(du.UsedPercent)
		out["disk_total_bytes"] = du.Total
	}
	if up, err := host.UptimeWithContext(ctx); err == nil {
		out["uptime_seconds"] = up
	}
	if kv, err := host.KernelVersionWithContext(ctx); err == nil && kv != "" {
		out["kernel_version"] = kv
	}
	if ips := hostIPs(); len(ips) > 0 {
		out["ip_addresses"] = ips
	}
	if runtime.GOOS != "windows" {
		if avg, err := load.AvgWithContext(ctx); err == nil {
			out["load_average"] = []float64{avg.Load1, avg.Load5, avg.Load15}
		}
	}
	return out
}

// hostIPs lists the addresses of interfaces that are up, skipping loopback and link-local, at most eight.
func hostIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ipnet.IP.String())
			if len(ips) == 8 {
				return ips
			}
		}
	}
	return ips
}
