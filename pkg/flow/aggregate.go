package flow

import (
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

// extractKey builds the 5-tuple string key and returns it plus its parts.
func extractKey(pkt gopacket.Packet) (key string, parts []string, timestamp time.Time) {
    timestamp = pkt.Metadata().Timestamp

    // Get IPv4 or IPv6 layer
    var (
        srcIP, dstIP string
        proto        string
        srcPort, dstPort string
    )

    if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
        v4 := ip4.(*layers.IPv4)
        srcIP, dstIP = v4.SrcIP.String(), v4.DstIP.String()
    } else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
        v6 := ip6.(*layers.IPv6)
        srcIP, dstIP = v6.SrcIP.String(), v6.DstIP.String()
    }

    // Get transport layer
    if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
        t := tcp.(*layers.TCP)
        proto = "TCP"
        srcPort, dstPort = t.SrcPort.String(), t.DstPort.String()
    } else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
        u := udp.(*layers.UDP)
        proto = "UDP"
        srcPort, dstPort = u.SrcPort.String(), u.DstPort.String()
    }

    parts = []string{srcIP, dstIP, proto, srcPort, dstPort}
    key = strings.Join(parts, "-")
    return
}

// Aggregate reads packets from ch, groups them into flows, and returns them.
func Aggregate(ch <-chan gopacket.Packet) []*Flow {
    flows := make(map[string]*Flow)

    for pkt := range ch {
        key, parts, ts := extractKey(pkt)
        size := len(pkt.Data())

        if f, exists := flows[key]; !exists {
            // first packet of this flow
            flows[key] = newFlow(pkt, parts)
        } else {
            // update existing flow
            f.PacketCount++
            f.ByteCount += size

            // compute inter-arrival time
            iat := ts.Sub(f.LastSeen)
            f.IATs = append(f.IATs, iat)

            f.PacketSizes = append(f.PacketSizes, size)
            f.LastSeen = ts
        }
    }

    // convert map to slice
    result := make([]*Flow, 0, len(flows))
    for _, f := range flows {
        result = append(result, f)
    }
    return result
}
