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

    fmt.Printf("Aggregated %d flows\n", len(flows))

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()
    <-ctx.Done()
    fmt.Println("Shutting down")
}
