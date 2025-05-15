package flow

import (
    "net"
    "strconv"
    "time"

    "github.com/google/gopacket"
)

// Flow holds per-flow stats and raw data for feature computation.
type Flow struct {
    SrcIP        net.IP
    DstIP        net.IP
    SrcPort      uint16
    DstPort      uint16
    Protocol     string
    FirstSeen    time.Time
    LastSeen     time.Time
    PacketCount  int
    ByteCount    int
    PacketSizes  []int
    IATs         []time.Duration
}

// parsePort turns a port string (“80”) into uint16.
func parsePort(s string) uint16 {
    p, _ := strconv.Atoi(s)
    return uint16(p)
}

// newFlow initializes a Flow from the very first packet.
func newFlow(pkt gopacket.Packet, keyParts []string) *Flow {
    // keyParts: [srcIP, dstIP, proto, srcPort, dstPort]
    now := pkt.Metadata().Timestamp
    size := len(pkt.Data())

    return &Flow{
        SrcIP:       net.ParseIP(keyParts[0]),
        DstIP:       net.ParseIP(keyParts[1]),
        Protocol:    keyParts[2],
        SrcPort:     parsePort(keyParts[3]),
        DstPort:     parsePort(keyParts[4]),
        FirstSeen:   now,
        LastSeen:    now,
        PacketCount: 1,
        ByteCount:   size,
        PacketSizes: []int{size},
        IATs:        nil,
    }
}
