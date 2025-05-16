package features

import (
    "time"
    "net"

    "github.com/Tushar98644/PacketSentry/pkg/flow"
    "github.com/Tushar98644/PacketSentry/pkg/stats"
)

type FlowFeatures struct {
    SrcIP      net.IP
    DstIP      net.IP
    SrcPort    uint16
    DstPort    uint16
    Protocol   string

    Duration time.Duration 

    PacketCount int

    PacketStats stats.IntStats
    IATStats    stats.DurationStats
}

func FromFlow(f *flow.Flow) FlowFeatures {
    srcIP := f.SrcIP
    dstIP := f.DstIP
    srcPort := f.SrcPort
    dstPort := f.DstPort
    protocol := f.Protocol

    duration := f.LastSeen.Sub(f.FirstSeen)

    pktStats := stats.ComputeIntStats(f.PacketSizes)

    iatStats := stats.ComputeDurationStats(f.IATs)

    return FlowFeatures{
        SrcIP:      srcIP,
        DstIP:      dstIP,
        SrcPort:    srcPort,
        DstPort:    dstPort,
        Protocol:   protocol,
        Duration:    duration,
        PacketCount: f.PacketCount,
        PacketStats: pktStats,
        IATStats:    iatStats,
    }
}
