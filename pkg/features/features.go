package features

import (
    "time"

    "github.com/Tushar98644/PacketSentry/pkg/flow"
    "github.com/Tushar98644/PacketSentry/pkg/stats"
)

type FlowFeatures struct {
    Duration time.Duration 

    PacketCount int

    PacketStats stats.IntStats
    IATStats    stats.DurationStats
}

func FromFlow(f *flow.Flow) FlowFeatures {
    duration := f.LastSeen.Sub(f.FirstSeen)

    pktStats := stats.ComputeIntStats(f.PacketSizes)

    iatStats := stats.ComputeDurationStats(f.IATs)

    return FlowFeatures{
        Duration:    duration,
        PacketCount: f.PacketCount,
        PacketStats: pktStats,
        IATStats:    iatStats,
    }
}
