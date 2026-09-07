//go:build containers_image_openpgp

package podman

import (
	"errors"
	"testing"

	"github.com/containers/podman/v5/libpod/define"
	entTypes "github.com/containers/podman/v5/pkg/domain/entities/types"
)

func TestUsageFromStatsReportUsesFirstCumulativeNetworkSnapshot(t *testing.T) {
	report := entTypes.ContainerStatsReport{Stats: []define.ContainerStats{{
		CPU:      12.5,
		MemUsage: 4096,
		Network: map[string]define.ContainerNetworkStats{
			"lo":   {RxBytes: 100, TxBytes: 200},
			"eth0": {RxBytes: 1024, TxBytes: 2048},
			"eth1": {RxBytes: 512, TxBytes: 256},
		},
	}}}

	cpu, mem, in, out, err := usageFromStatsReport(report)
	if err != nil {
		t.Fatalf("usageFromStatsReport() error = %v", err)
	}
	if cpu != 12.5 || mem != 4096 || in != 1536 || out != 2304 {
		t.Fatalf("usageFromStatsReport() = cpu=%v mem=%d in=%d out=%d", cpu, mem, in, out)
	}
}

func TestUsageFromStatsReportRejectsMissingOrErroredReports(t *testing.T) {
	for _, report := range []entTypes.ContainerStatsReport{
		{Error: errors.New("socket closed")},
		{},
	} {
		if _, _, _, _, err := usageFromStatsReport(report); err == nil {
			t.Fatal("usageFromStatsReport() accepted an invalid report")
		}
	}
}
