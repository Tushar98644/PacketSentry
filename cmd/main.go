// cmd/main.go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"

    gp "github.com/google/gopacket/pcap"

    "github.com/Tushar98644/PacketSentry/pkg/config"
    "github.com/Tushar98644/PacketSentry/pkg/pcap"
    "github.com/Tushar98644/PacketSentry/pkg/flow"
    "github.com/Tushar98644/PacketSentry/pkg/features"
)

func main() {
    cfg := config.New()
    cfg.ParseFlags()
    if err := cfg.Validate(); err != nil {
        log.Fatalf("config error: %v", err)
    }

    if cfg.LiveCapture {
        devs, err := gp.FindAllDevs()
        if err != nil {
            log.Fatalf("could not list devices: %v", err)
        }
        fmt.Println("Available devices:")
        for _, d := range devs {
            fmt.Printf("  - %s: %s\n", d.Name, d.Description)
        }
        fmt.Printf("Using device: %s\n\n", cfg.Device)
    }

    handle, err := pcap.OpenHandle(cfg)
    if err != nil {
        log.Fatalf("could not open handle: %v", err)
    }
    defer handle.Close()

    packetCh := pcap.ReadPackets(handle)
    flows := flow.Aggregate(packetCh)

    fmt.Printf("Computed features for %d flows:\n\n", len(flows))

    for i, f := range flows {
        feats := features.FromFlow(f)
        fmt.Printf("Flow %d:\n", i+1)
        fmt.Printf("  Duration: %v\n", feats.Duration)
        fmt.Printf("  Packet count: %d\n", feats.PacketCount)
        fmt.Printf("  Packet size → count=%d mean=%.2f min=%d max=%d std=%.2f\n",
            feats.PacketStats.Count,
            feats.PacketStats.Mean,
            feats.PacketStats.Min,
            feats.PacketStats.Max,
            feats.PacketStats.Std,
        )
        fmt.Printf("  IAT → count=%d mean=%v min=%v max=%v std=%v\n\n",
            feats.IATStats.Count,
            feats.IATStats.Mean,
            feats.IATStats.Min,
            feats.IATStats.Max,
            feats.IATStats.Std,
        )
    }

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()
    <-ctx.Done()
    fmt.Println("Shutting down")
}
